<#
.SYNOPSIS
    Builds netskope-cert-bundle.pem (Netskope tenant CAs + Mozilla root bundle) from the
    Netskope certificates that sit next to this script. Non-interactive.

.DESCRIPTION
    Intended for the admin/packaging machine. Download the certificates from the tenant
    (Settings > Manage > Certificates > Netskope Certificates), save them next to this script
    with the standard names below, then run this script. The output, netskope-cert-bundle.pem,
    is what silent_configure_tools_windows.ps1 deploys to endpoints (default C:\netskope).

      Standard name                  Tenant download                                Required
      netskope-root-ca.pem           Netskope root certificate.pem                  yes
      netskope-intermediate-ca.pem   Netskope intermediate certificate.pem          recommended
      netskope-remote-users-ca.pem   Netskope root certificate (remote users).pem   recommended

    The root CA is what signs the inspected traffic seen by the Netskope Client, so the build
    fails without it. A missing intermediate or remote-users certificate is a warning.

    Before writing, the certificates are sanity-checked so a wrong or swapped file is caught on
    the admin machine instead of on every endpoint:
      - every file must contain exactly one valid X.509 certificate
      - the root and remote-users certificates must be self-signed
      - the intermediate must chain to the root (issuer name and signature)
      - expired certificates fail the build; certificates expiring within 90 days warn
      - the same certificate under two names fails the build

    Output order: root, intermediate, remote users, then the Mozilla roots. Line endings are
    normalised to LF and the file is written atomically.

.PARAMETER Dir
    Directory holding the input certificates and receiving the output. Default: the script's
    directory.

.PARAMETER RootName
    Root CA filename. Default: netskope-root-ca.pem.

.PARAMETER IntermediateName
    Intermediate CA filename. Default: netskope-intermediate-ca.pem.

.PARAMETER RemoteUsersName
    Remote-users root CA filename. Default: netskope-remote-users-ca.pem.

.PARAMETER OutputName
    Bundle filename. Default: netskope-cert-bundle.pem.

.PARAMETER MozillaBundlePath
    Use this local copy of the Mozilla bundle (cacert.pem) instead of downloading it.
    For offline/air-gapped packaging.

.EXAMPLE
    .\build_cert_bundle_windows.ps1

.EXAMPLE
    .\build_cert_bundle_windows.ps1 -MozillaBundlePath .\cacert.pem
#>
[CmdletBinding()]
param(
    [string]$Dir,
    [string]$RootName         = 'netskope-root-ca.pem',
    [string]$IntermediateName = 'netskope-intermediate-ca.pem',
    [string]$RemoteUsersName  = 'netskope-remote-users-ca.pem',
    [string]$OutputName       = 'netskope-cert-bundle.pem',
    [string]$MozillaBundlePath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}

$MozillaUrl      = 'https://curl.se/ca/cacert.pem'
$MozillaMinCerts = 100     # cacert.pem carries ~140; far fewer means an error page / truncation
$ExpiryWarnDays  = 90
$pemRegex = '-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----'

# Returns one object per certificate: canonical PEM text (64-column, LF) + parsed X509Certificate2.
function Get-PemCerts([string]$Path, [string]$Label) {
    $raw = [System.IO.File]::ReadAllText($Path)
    $certs = @()
    foreach ($m in [regex]::Matches($raw, $pemRegex)) {
        $b64 = ($m.Value -replace '-----(BEGIN|END) CERTIFICATE-----', '') -replace '\s', ''
        try { $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64)) }
        catch { throw "$Label contains a block that is not a valid certificate: $($_.Exception.Message)" }
        $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
        $certs += [pscustomobject]@{
            Pem  = "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----"
            Cert = $x509
        }
    }
    if ($certs.Count -eq 0) { throw "$Label has no PEM certificates: $Path" }
    return $certs
}

function Test-SelfSigned($Cert) {
    return (($Cert.SubjectName.RawData -join ',') -eq ($Cert.IssuerName.RawData -join ','))
}

# True when $Child is issued and signed by $Issuer. Builds the chain with $Issuer as the only
# extra certificate and an unknown root allowed (the Netskope root need not be in the Windows
# store of the packaging machine), then requires the chain to end at $Issuer with no signature
# or constraint errors.
function Test-IssuedBy($Child, $Issuer) {
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode    = 'NoCheck'
        $chain.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority, IgnoreNotTimeValid'
        $null = $chain.ChainPolicy.ExtraStore.Add($Issuer)
        $null = $chain.Build($Child)
        if ($chain.ChainElements.Count -lt 2) { return $false }
        if ($chain.ChainElements[1].Certificate.Thumbprint -ne $Issuer.Thumbprint) { return $false }
        $bad = 'NotSignatureValid', 'InvalidBasicConstraints', 'InvalidNameConstraints', 'Cyclic'
        foreach ($s in $chain.ChainStatus) { if ($bad -contains [string]$s.Status) { return $false } }
        return $true
    } finally { $chain.Reset() }
}

function Format-Cert($Cert) {
    $days = [int][Math]::Floor(($Cert.NotAfter - (Get-Date)).TotalDays)
    return ("    subject : {0}`n    issuer  : {1}`n    valid   : {2:yyyy-MM-dd} to {3:yyyy-MM-dd} ({4} days left)`n    SHA1    : {5}" -f
        $Cert.Subject, $Cert.Issuer, $Cert.NotBefore, $Cert.NotAfter, $days, $Cert.Thumbprint)
}

# TLS validation that trusts only the Netskope CA certificates being bundled. Used when the
# packaging machine sits behind Netskope SSL inspection but does not trust the tenant CA yet.
# Compiled C# instead of a PowerShell scriptblock: .NET may invoke the callback on a thread
# with no PowerShell runspace. The hostname must still match; only the chain is re-checked,
# and it must end at one of the given Netskope certificates (matched by thumbprint).
$netskopeTlsSource = @'
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class NetskopeBundleTls {
    public static readonly X509Certificate2Collection Anchors = new X509Certificate2Collection();

    public static bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        if (errors == SslPolicyErrors.None) return true;
        if (certificate == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0) return false;
        using (X509Certificate2 leaf = new X509Certificate2(certificate))
        using (X509Chain c = new X509Chain()) {
            c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            c.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            c.ChainPolicy.ExtraStore.AddRange(Anchors);
            if (chain != null) {
                foreach (X509ChainElement e in chain.ChainElements) c.ChainPolicy.ExtraStore.Add(e.Certificate);
            }
            c.Build(leaf);
            foreach (X509ChainStatus s in c.ChainStatus) {
                if (s.Status != X509ChainStatusFlags.NoError && s.Status != X509ChainStatusFlags.UntrustedRoot) return false;
            }
            if (c.ChainElements.Count < 2) return false;
            string root = c.ChainElements[c.ChainElements.Count - 1].Certificate.Thumbprint;
            foreach (X509Certificate2 a in Anchors) {
                if (string.Equals(a.Thumbprint, root, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    public static void Download(string url, string path, int timeoutMs) {
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
        req.Timeout = timeoutMs;
        req.ReadWriteTimeout = timeoutMs;
        req.ServerCertificateValidationCallback = Validate;
        using (WebResponse resp = req.GetResponse())
        using (Stream body = resp.GetResponseStream())
        using (FileStream file = File.Create(path)) {
            body.CopyTo(file);
        }
    }
}
'@

# Public download, most to least strict. The result is validated below (cert count + parse)
# before use either way.
#   1. normal TLS verification (works when the machine already trusts the tenant CA, or the
#      host is not inspected)
#   2. TLS verified against the Netskope CA certificates being bundled (behind SSL inspection
#      on a machine that does not trust the tenant CA yet: the very thing being built)
#   3. no verification (last resort, e.g. some other proxy re-signs the traffic)
function Get-MozillaBundle([string]$OutFile, $TrustAnchors) {
    $p = @{ Uri = $MozillaUrl; UseBasicParsing = $true; TimeoutSec = 60; OutFile = $OutFile }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    try { Invoke-WebRequest @p | Out-Null; return }
    catch { Write-Warning "Verified download failed ($($_.Exception.Message)); retrying trusting only the Netskope CA certificates being bundled." }

    try {
        if (-not ('NetskopeBundleTls' -as [type])) {
            # -IgnoreWarnings: WebRequest is marked obsolete on PowerShell 7 (.NET 6+) but works.
            Add-Type -TypeDefinition $netskopeTlsSource -IgnoreWarnings -WarningAction SilentlyContinue
        }
        [NetskopeBundleTls]::Anchors.Clear()
        foreach ($a in $TrustAnchors) { $null = [NetskopeBundleTls]::Anchors.Add($a) }
        [NetskopeBundleTls]::Download($MozillaUrl, $OutFile, 60000)
        Write-Host '  Downloaded over TLS verified against the Netskope CA.'
        return
    } catch {
        $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Warning "Download verified against the Netskope CA failed ($msg); retrying without certificate verification."
    }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Invoke-WebRequest @p -SkipCertificateCheck | Out-Null; return
    }
    $old = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Invoke-WebRequest @p | Out-Null
    } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $old }
}

$tmpOut = $null
try {
    $outputPath = Join-Path $Dir $OutputName

    # Role table, in output order.
    $roles = @(
        [pscustomobject]@{ Key = 'root';         Label = 'Netskope root CA';         File = $RootName;         Required = $true;  Download = 'Netskope root certificate.pem' }
        [pscustomobject]@{ Key = 'intermediate'; Label = 'Netskope intermediate CA'; File = $IntermediateName; Required = $false; Download = 'Netskope intermediate certificate.pem' }
        [pscustomobject]@{ Key = 'remote-users'; Label = 'Netskope remote-users CA'; File = $RemoteUsersName;  Required = $false; Download = 'Netskope root certificate (remote users).pem' }
    )

    # Old single-input layout: explain how to migrate instead of a bare "not found".
    $rootPath = Join-Path $Dir $RootName
    if (-not (Test-Path -LiteralPath $rootPath) -and (Test-Path -LiteralPath (Join-Path $Dir 'netskope-cert.pem'))) {
        throw ("Found the old input 'netskope-cert.pem' but not '$RootName'. The build now takes the tenant certificates " +
               "under standard names: download them from Settings > Manage > Certificates > Netskope Certificates and save " +
               "them as $RootName, $IntermediateName and $RemoteUsersName (see README). " +
               "Note: 'netskope-cert.pem' usually holds the remote-users CA, which alone does NOT fix SSL inspection errors.")
    }

    $found = @{}
    foreach ($r in $roles) {
        $path = Join-Path $Dir $r.File
        if (-not (Test-Path -LiteralPath $path)) {
            $msg = "$($r.Label) not found: $path (tenant download: '$($r.Download)')"
            if ($r.Required) { throw $msg }
            Write-Warning "$msg - building without it."
            continue
        }
        $certs = @(Get-PemCerts $path $r.Label)
        if ($certs.Count -ne 1) { throw "$($r.Label) file must contain exactly one certificate, found $($certs.Count): $path" }
        $found[$r.Key] = $certs[0]
        Write-Host "$($r.Label): $path"
        Write-Host (Format-Cert $certs[0].Cert)
    }

    # ---- Sanity checks: catch wrong / swapped files before they are deployed ----
    $root = $found['root'].Cert
    if (-not (Test-SelfSigned $root)) {
        throw "$RootName is not a self-signed root (issuer '$($root.Issuer)'). Is it the intermediate certificate?"
    }
    if ($found.ContainsKey('intermediate')) {
        $int = $found['intermediate'].Cert
        if (Test-SelfSigned $int) {
            throw "$IntermediateName is self-signed, so it is not the intermediate CA. Check that the files were not swapped."
        }
        if (-not (Test-IssuedBy $int $root)) {
            throw ("$IntermediateName (issuer '$($int.Issuer)') is not signed by $RootName ('$($root.Subject)'). " +
                   "The root and intermediate must come from the same tenant; re-download both.")
        }
        Write-Host "Check: intermediate CA is signed by the root CA - OK"
    }
    if ($found.ContainsKey('remote-users') -and -not (Test-SelfSigned $found['remote-users'].Cert)) {
        throw "$RemoteUsersName is not a self-signed root (issuer '$($found['remote-users'].Cert.Issuer)')."
    }
    $seen = @{}
    foreach ($r in $roles) {
        if (-not $found.ContainsKey($r.Key)) { continue }
        $c = $found[$r.Key].Cert
        if ($seen.ContainsKey($c.Thumbprint)) { throw "$($r.File) is the same certificate as $($seen[$c.Thumbprint]). Check the file names." }
        $seen[$c.Thumbprint] = $r.File
        $days = ($c.NotAfter - (Get-Date)).TotalDays
        if ($days -lt 0)                 { throw "$($r.File) EXPIRED on $($c.NotAfter.ToString('yyyy-MM-dd')). Download the current certificate from the tenant." }
        if ($days -lt $ExpiryWarnDays)   { Write-Warning "$($r.File) expires on $($c.NotAfter.ToString('yyyy-MM-dd')) (in $([int]$days) days) - plan a rebuild." }
        if ((Get-Date) -lt $c.NotBefore) { Write-Warning "$($r.File) is not valid until $($c.NotBefore.ToString('yyyy-MM-dd')) - check the clock or the certificate." }
    }

    $nsRoles  = @($roles | Where-Object { $found.ContainsKey($_.Key) })
    $nsBlocks = @($nsRoles | ForEach-Object { $found[$_.Key].Pem })
    $nsKeys   = ($nsRoles | ForEach-Object { $_.Key }) -join ', '

    # ---- Mozilla roots ----
    $mozTemp = $null
    $mozSource = $MozillaBundlePath
    if (-not $mozSource) {
        $mozTemp = [System.IO.Path]::GetTempFileName()
        Write-Host "Downloading Mozilla CA bundle: $MozillaUrl"
        Get-MozillaBundle $mozTemp @($nsRoles | ForEach-Object { $found[$_.Key].Cert })
        $mozSource = $mozTemp
    } elseif (-not (Test-Path -LiteralPath $mozSource)) {
        throw "Mozilla bundle not found: $mozSource"
    }
    try {
        $mozBlocks = @(Get-PemCerts $mozSource 'Mozilla bundle' | ForEach-Object { $_.Pem })
        if ($mozBlocks.Count -lt $MozillaMinCerts) {
            throw "Mozilla bundle has only $($mozBlocks.Count) certificates (expected >= $MozillaMinCerts)"
        }
        Write-Host "Mozilla roots: $($mozBlocks.Count) certificate(s)"
    } finally {
        if ($mozTemp) { Remove-Item -LiteralPath $mozTemp -ErrorAction SilentlyContinue }
    }

    # The count header tells silent_configure_tools_* which leading certs are the Netskope CA
    # (used to check/merge existing CA bundles). The netskope-certs line is informational only.
    # PEM readers ignore text outside cert blocks.
    $header  = "# Netskope SSL inspection trust bundle: Netskope tenant CAs + Mozilla roots`n" +
               "# Generated by build_cert_bundle_windows.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" +
               "# netskope-certs: $nsKeys`n" +
               "# netskope-cert-count: $($nsBlocks.Count)`n"
    $content = $header + (($nsBlocks + $mozBlocks) -join "`n") + "`n"
    $tmpOut  = "$outputPath.tmp"
    [System.IO.File]::WriteAllText($tmpOut, $content, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmpOut -Destination $outputPath -Force

    Write-Host ''
    Write-Host "Bundle written: $outputPath ($($nsBlocks.Count + $mozBlocks.Count) certificates: $($nsBlocks.Count) Netskope [$nsKeys] + $($mozBlocks.Count) Mozilla)"
    exit 0
} catch {
    Write-Error "Failed to build bundle: $($_.Exception.Message)" -ErrorAction Continue
    if ($tmpOut) { Remove-Item -LiteralPath $tmpOut -ErrorAction SilentlyContinue }
    exit 1
}
