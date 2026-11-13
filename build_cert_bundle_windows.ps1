<#
.SYNOPSIS
    Builds netskope-cert-bundle.pem (Netskope tenant CA + Mozilla root bundle) from a
    netskope-cert.pem that sits next to this script. Non-interactive.

.DESCRIPTION
    Intended for the admin/packaging machine. Obtain the tenant CA yourself (Netskope UI,
    API, or a machine where the client config is not protected), save it as
    netskope-cert.pem next to this script, then run this script. The output,
    netskope-cert-bundle.pem, is what silent_configure_tools_windows.ps1 deploys to endpoints
    (default location C:\netskope).

    The Netskope certificate(s) are placed first, followed by the Mozilla roots. Input is
    validated (every block must parse as an X.509 certificate), normalised to LF line endings
    and the output is written atomically.

.PARAMETER Dir
    Directory holding the input cert and receiving the output. Default: the script's directory.

.PARAMETER InputName
    Netskope tenant CA filename. Default: netskope-cert.pem.

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
    [string]$InputName  = 'netskope-cert.pem',
    [string]$OutputName = 'netskope-cert-bundle.pem',
    [string]$MozillaBundlePath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}

$MozillaUrl      = 'https://curl.se/ca/cacert.pem'
$MozillaMinCerts = 100     # cacert.pem carries ~140; far fewer means an error page / truncation
$pemRegex = '-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----'

function Get-PemBlocks([string]$Path, [string]$Label) {
    $raw = [System.IO.File]::ReadAllText($Path)
    $blocks = @()
    foreach ($m in [regex]::Matches($raw, $pemRegex)) {
        $b64 = ($m.Value -replace '-----(BEGIN|END) CERTIFICATE-----', '') -replace '\s', ''
        try { $null = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64)) }
        catch { throw "$Label contains a block that is not a valid certificate: $($_.Exception.Message)" }
        # Re-emit with canonical 64-column wrapping and LF endings.
        $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
        $blocks += ("-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----")
    }
    if ($blocks.Count -eq 0) { throw "$Label has no PEM certificates: $Path" }
    return $blocks
}

# Public download: verify TLS first; only fall back to unverified when the host sits behind
# SSL inspection whose CA is not trusted yet (the very thing being built). The result is
# validated below (cert count + parse) before use.
function Get-MozillaBundle([string]$OutFile) {
    $p = @{ Uri = $MozillaUrl; UseBasicParsing = $true; TimeoutSec = 60; OutFile = $OutFile }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    try { Invoke-WebRequest @p | Out-Null; return }
    catch { Write-Warning "Verified download failed ($($_.Exception.Message)); retrying without certificate verification." }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Invoke-WebRequest @p -SkipCertificateCheck | Out-Null; return
    }
    $old = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Invoke-WebRequest @p | Out-Null
    } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $old }
}

try {
    $inputPath  = Join-Path $Dir $InputName
    $outputPath = Join-Path $Dir $OutputName
    if (-not (Test-Path -LiteralPath $inputPath)) { throw "Input certificate not found: $inputPath" }

    Write-Host "Reading Netskope CA: $inputPath"
    $nsBlocks = Get-PemBlocks $inputPath 'Netskope certificate file'
    Write-Host "  $($nsBlocks.Count) certificate(s)"

    $mozTemp = $null
    $mozSource = $MozillaBundlePath
    if (-not $mozSource) {
        $mozTemp = [System.IO.Path]::GetTempFileName()
        Write-Host "Downloading Mozilla CA bundle: $MozillaUrl"
        Get-MozillaBundle $mozTemp
        $mozSource = $mozTemp
    } elseif (-not (Test-Path -LiteralPath $mozSource)) {
        throw "Mozilla bundle not found: $mozSource"
    }

    try {
        $mozBlocks = Get-PemBlocks $mozSource 'Mozilla bundle'
        if ($mozBlocks.Count -lt $MozillaMinCerts) {
            throw "Mozilla bundle has only $($mozBlocks.Count) certificates (expected >= $MozillaMinCerts)"
        }
        Write-Host "  $($mozBlocks.Count) certificate(s)"
    } finally {
        if ($mozTemp) { Remove-Item -LiteralPath $mozTemp -ErrorAction SilentlyContinue }
    }

    # The count header tells silent_configure_tools_* which leading certs are the Netskope CA
    # (used to check/merge existing CA bundles). PEM readers ignore text outside cert blocks.
    $header  = "# Netskope SSL inspection trust bundle: Netskope tenant CA + Mozilla roots`n" +
               "# Generated by build_cert_bundle_windows.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" +
               "# netskope-cert-count: $($nsBlocks.Count)`n"
    $content = $header + (($nsBlocks + $mozBlocks) -join "`n") + "`n"
    $tmpOut  = "$outputPath.tmp"
    [System.IO.File]::WriteAllText($tmpOut, $content, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmpOut -Destination $outputPath -Force

    Write-Host ''
    Write-Host "Bundle written: $outputPath ($($nsBlocks.Count + $mozBlocks.Count) certificates: $($nsBlocks.Count) Netskope + $($mozBlocks.Count) Mozilla)"
    exit 0
} catch {
    Write-Error "Failed to build bundle: $($_.Exception.Message)"
    if ($tmpOut) { Remove-Item -LiteralPath $tmpOut -ErrorAction SilentlyContinue }
    exit 1
}
