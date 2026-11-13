<#
.SYNOPSIS
    Silently configures developer CLIs/apps to trust the Netskope CA bundle. Built for
    GPO / MDM (Intune, SCCM...) deployment: never prompts, never needs a token.

.DESCRIPTION
    Expects a ready-made bundle (see build_cert_bundle_windows.ps1). If a copy of the bundle
    sits next to this script it is installed to -CertDir first, so a deployment package can
    simply be {this script + netskope-cert-bundle.pem}.

    Environment variables (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, ...) are
    configured whether or not the tool is installed today. When a variable already has a
    value, the script decides per value instead of blindly overwriting:

      unset / file missing / not a cert file      -> set to the Netskope bundle
      already the Netskope bundle                 -> leave
      a previous Netskope bundle (other path)     -> replace with the Netskope bundle
      a custom bundle that already has the CA     -> leave (it already trusts Netskope)
      a custom bundle WITHOUT the Netskope CA     -> merge: write custom certs + Netskope CA
                                                     to <CertDir>\merged\ and point there,
                                                     so internal/private CAs keep working
      a directory, or an unreadable file          -> leave, log WARN
    -Force skips the analysis and always sets the Netskope bundle.

    Run as SYSTEM/administrator (GPO startup script / Intune): machine-scope variables are
    configured, and every user profile's per-user variables are checked too, because a
    per-user value silently overrides the machine one. Run as a normal user: the user's
    effective value (user, else machine) is checked and only user scope is written.

    File/directory based configuration (git config, Azure Storage Explorer certs dir) is
    applied only when the tool is present; otherwise it is skipped and the skip is logged.

    Everything is appended to a log (default %PUBLIC%\netskope-ssl-configure-tools.log).
    Every decision line states the current value, where it was read from, why it was kept
    or changed, and the new value.

    Exit codes: 0 = done (skips are not errors), 2 = done but some step failed (see log),
                1 = fatal (e.g. bundle missing).

.PARAMETER CertDir
    Where the bundle lives on the endpoint. Default: C:\netskope.

.PARAMETER CertName
    Bundle filename. Default: netskope-cert-bundle.pem.

.PARAMETER LogPath
    Log file. Default: %PUBLIC%\netskope-ssl-configure-tools.log.

.PARAMETER Scope
    Auto (default): Machine when elevated, otherwise User. 'Process' only affects this
    process and exists for testing.

.PARAMETER Force
    Always set every variable to the Netskope bundle, replacing any existing value.

.PARAMETER DryRun
    Log what would be changed without changing anything.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\silent_configure_tools_windows.ps1
#>
[CmdletBinding()]
param(
    [string]$CertDir  = 'C:\netskope',
    [string]$CertName = 'netskope-cert-bundle.pem',
    [string]$LogPath,
    [ValidateSet('Auto', 'Machine', 'User', 'Process')][string]$Scope = 'Auto',
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$script:Version   = '1.2'
$script:Counts    = @{ INFO = 0; OK = 0; SKIP = 0; WARN = 0; ERROR = 0 }
$script:StartTime = Get-Date

# ============================================================
# Logging
# ============================================================
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $pub = if ($env:PUBLIC) { $env:PUBLIC } else { 'C:\Users\Public' }
    $LogPath = Join-Path $pub 'netskope-ssl-configure-tools.log'
}
$script:LogPath = $LogPath
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-Log {
    param([ValidateSet('INFO', 'OK', 'SKIP', 'WARN', 'ERROR')][string]$Level, [string]$Message)
    $script:Counts[$Level]++
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    # Logging must never break the run. Retry briefly: several users' logon scripts may
    # append at the same moment.
    for ($i = 0; $i -lt 3; $i++) {
        try { [System.IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, $utf8NoBom); return }
        catch { Start-Sleep -Milliseconds 150 }
    }
}

function Initialize-Log {
    try {
        $dir = Split-Path -Parent $script:LogPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # Keep one previous generation once the log passes 2 MB.
        if ((Test-Path -LiteralPath $script:LogPath) -and (Get-Item -LiteralPath $script:LogPath).Length -gt 2MB) {
            Move-Item -LiteralPath $script:LogPath -Destination "$($script:LogPath).old" -Force
        }
        if (-not (Test-Path -LiteralPath $script:LogPath)) {
            [System.IO.File]::WriteAllText($script:LogPath, '', $utf8NoBom)
            # Let every user append (the first run is usually SYSTEM; later ones are users).
            if ($script:IsAdmin) { & icacls.exe $script:LogPath /grant '*S-1-5-32-545:(M)' 2>&1 | Out-Null }
        }
    } catch { }
}

function Format-Value([string]$Value) { if ([string]::IsNullOrEmpty($Value)) { '(unset)' } else { "'$Value'" } }
function Get-ShortHash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.Substring(0, 16) }

# ============================================================
# Context
# ============================================================
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Initialize-Log

$envTarget = $Scope
if ($Scope -eq 'Auto') { $envTarget = if ($script:IsAdmin) { 'Machine' } else { 'User' } }

$bundlePath = Join-Path $CertDir $CertName
# Merged bundles must be readable by every user they serve. Elevated: next to the bundle.
# Non-elevated: the user's own profile (C:\netskope is admin-owned).
$mergeDir = if ($envTarget -eq 'User') { Join-Path $env:LOCALAPPDATA 'netskope\merged' } else { Join-Path $CertDir 'merged' }

Write-Log INFO "===== netskope-ssl-configure-tools v$($script:Version) start ====="
$os = try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    "$($cv.ProductName) $($cv.DisplayVersion) (build $($cv.CurrentBuild).$($cv.UBR))"
} catch { [Environment]::OSVersion.VersionString }
Write-Log INFO "Host: $env:COMPUTERNAME | OS: $os | PowerShell $($PSVersionTable.PSVersion)"
Write-Log INFO ("Run as: {0}\{1} | elevated={2} | env scope={3} | force={4} | dryrun={5}" -f $env:USERDOMAIN, $env:USERNAME, $script:IsAdmin, $envTarget, [bool]$Force, [bool]$DryRun)
Write-Log INFO "Script: $PSCommandPath | log: $($script:LogPath)"
Write-Log INFO "Bundle target: $bundlePath | merged bundles: $mergeDir"
if ($Scope -eq 'Machine' -and -not $script:IsAdmin) {
    Write-Log WARN 'Scope Machine requested but the process is not elevated; falling back to User.'
    $envTarget = 'User'
}

# ============================================================
# Helpers
# ============================================================
$pemRegex = '-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----'

# Base64 body of each cert, whitespace stripped - comparable regardless of wrapping/CRLF.
function Get-CertBodies([string]$Text) {
    foreach ($m in [regex]::Matches($Text, $pemRegex)) {
        ($m.Value -replace '-----(BEGIN|END) CERTIFICATE-----', '') -replace '\s', ''
    }
}

function ConvertTo-NormPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim().Trim('"') -replace '/', '\'
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { }
    return $p.TrimEnd('\').ToLowerInvariant()
}
function Test-SamePath([string]$A, [string]$B) { return (ConvertTo-NormPath $A) -eq (ConvertTo-NormPath $B) }

function Find-Exe([string[]]$Names, [string[]]$ExtraPaths = @()) {
    foreach ($n in $Names) {
        $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    foreach ($p in $ExtraPaths) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
    return $null
}

# Profiles to configure: every real user profile when elevated, otherwise the current one.
function Get-TargetProfiles {
    if ($envTarget -eq 'Machine') {
        $list = @()
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($k in Get-ChildItem $key -ErrorAction SilentlyContinue) {
            if ($k.PSChildName -notmatch '^S-1-5-21-') { continue }   # skips service accounts
            $path = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if ($path -and (Test-Path -LiteralPath $path)) { $list += [pscustomobject]@{ Sid = $k.PSChildName; Path = $path } }
        }
        return $list
    }
    return @([pscustomobject]@{ Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; Path = $env:USERPROFILE })
}

# ============================================================
# Step 1: make sure the bundle is in place and sane
# ============================================================
Write-Log INFO '--- Bundle ---'
try {
    $shipped = if ($PSScriptRoot) { Join-Path $PSScriptRoot $CertName } else { $null }
    if (-not $shipped -or -not (Test-Path -LiteralPath $shipped)) {
        Write-Log INFO "No bundle shipped next to the script ($shipped); using the one already at $bundlePath"
    } elseif (Test-SamePath $shipped $bundlePath) {
        Write-Log INFO 'Script runs from the bundle directory; nothing to install'
    } else {
        $newHash = Get-ShortHash $shipped
        $oldHash = if (Test-Path -LiteralPath $bundlePath) { Get-ShortHash $bundlePath } else { $null }
        if ($oldHash -eq $newHash) {
            Write-Log SKIP "Bundle install: no change - installed bundle is identical to the shipped one (SHA256 $newHash...)"
        } elseif ($DryRun) {
            Write-Log INFO "DRY-RUN would install bundle: $shipped -> $bundlePath (SHA256 $(if ($oldHash) { "$oldHash... -> " })$newHash...)"
        } else {
            if (-not (Test-Path -LiteralPath $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }
            $tmp = "$bundlePath.tmp"
            Copy-Item -LiteralPath $shipped -Destination $tmp -Force
            Move-Item -LiteralPath $tmp -Destination $bundlePath -Force
            $why = if ($oldHash) { "replaced a different bundle (SHA256 $oldHash... -> $newHash...)" } else { "first install (SHA256 $newHash...)" }
            Write-Log OK "Bundle installed: $shipped -> $bundlePath - $why"
        }
    }

    if (-not (Test-Path -LiteralPath $bundlePath)) {
        if ($DryRun -and $shipped -and (Test-Path -LiteralPath $shipped)) { $bundlePath = $shipped }
        else { throw "Bundle not found: $bundlePath (deploy $CertName next to this script or to $CertDir)" }
    }
    $bundleText = [System.IO.File]::ReadAllText($bundlePath)
    $allBlocks  = @([regex]::Matches($bundleText, $pemRegex) | ForEach-Object { $_.Value })
    if ($allBlocks.Count -lt 2) { throw "Bundle looks invalid ($($allBlocks.Count) certificate(s)): $bundlePath" }
    $bi = Get-Item -LiteralPath $bundlePath
    Write-Log INFO ("Bundle OK: {0} certificate(s), {1} bytes, modified {2}, SHA256 {3}" -f $allBlocks.Count, $bi.Length, $bi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), (Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash)

    # The build script records how many leading certs are the Netskope CA. Without that we
    # cannot tell which certs to look for / merge, so custom bundles are left untouched.
    $nsBlocks = @()
    if ($bundleText -match '(?m)^# netskope-cert-count:\s*(\d+)') {
        $nsBlocks = @($allBlocks | Select-Object -First ([int]$Matches[1]))
        Write-Log INFO "Netskope CA = first $($nsBlocks.Count) certificate(s) of the bundle (from its netskope-cert-count header)"
        $i = 0
        foreach ($b in $nsBlocks) {
            $i++
            try {
                $b64 = ($b -replace '-----(BEGIN|END) CERTIFICATE-----', '') -replace '\s', ''
                $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
                $days = [int][Math]::Floor(($c.NotAfter - (Get-Date)).TotalDays)
                Write-Log INFO ("Netskope CA #{0}: subject '{1}' | issuer '{2}' | valid {3:yyyy-MM-dd} to {4:yyyy-MM-dd} ({5} days left) | SHA1 {6}" -f $i, $c.Subject, $c.Issuer, $c.NotBefore, $c.NotAfter, $days, $c.Thumbprint)
                if ($days -lt 0)       { Write-Log WARN "Netskope CA #$i EXPIRED on $($c.NotAfter.ToString('yyyy-MM-dd')) - rebuild the bundle with the current tenant CA" }
                elseif ($days -lt 30)  { Write-Log WARN "Netskope CA #$i expires in $days day(s) - plan a bundle rebuild" }
            } catch { Write-Log WARN "Netskope CA #$i could not be parsed: $($_.Exception.Message)" }
        }
    } else {
        Write-Log WARN 'Bundle has no "# netskope-cert-count" header (not built by build_cert_bundle_*); existing custom CA bundles will be left as they are instead of being checked/merged. Rebuild the bundle to enable merging.'
    }
    $nsBodies = @($nsBlocks | ForEach-Object { Get-CertBodies $_ })
} catch {
    Write-Log ERROR "Fatal: $($_.Exception.Message)"
    Write-Log INFO '===== finished with FATAL error ====='
    exit 1
}

# Lock the bundle directory down: by default, folders created under C:\ inherit "Authenticated
# Users: Modify", which would let any user swap the machine-wide trust bundle. Only touched
# when the folder is clearly ours (leaf name contains "netskope") - never a drive root.
if ($envTarget -eq 'Machine' -and -not $DryRun) {
    if ((Split-Path -Leaf $CertDir) -match 'netskope') {
        try {
            & icacls.exe $CertDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "icacls exited $LASTEXITCODE" }
            Write-Log INFO "Permissions enforced on $CertDir (SYSTEM/Administrators: full control, Users: read-only)"
        } catch { Write-Log WARN "Could not set permissions on $CertDir : $($_.Exception.Message)" }
    } else {
        Write-Log INFO "Permissions on $CertDir not changed (folder name does not contain 'netskope')"
    }
}

# ============================================================
# Decision logic for an existing variable value
# ============================================================
function New-Decision($Action, $Reason, $Source = $null, $Level = 'SKIP') {
    [pscustomobject]@{ Action = $Action; Reason = $Reason; Source = $Source; Level = $Level }
}

# Action: Skip (already ours) | Keep (leave existing value) | Set (Netskope bundle) | Merge
# Reason: a full sentence explaining the evidence (shown in the log).
function Get-Decision([string]$Current) {
    if ([string]::IsNullOrWhiteSpace($Current)) { return New-Decision 'Set' 'variable was not set' }
    $cur = $Current.Trim().Trim('"')
    if (Test-SamePath $cur $bundlePath) { return New-Decision 'Skip' 'value already points to the Netskope bundle' }
    if ($Force) { return New-Decision 'Set' '-Force: replaced without inspecting the existing value' }

    $isFile = $false; $isDir = $false
    try { $isFile = Test-Path -LiteralPath $cur -PathType Leaf; $isDir = Test-Path -LiteralPath $cur -PathType Container } catch { }

    $text = $null
    if ($isFile) {
        try { $text = [System.IO.File]::ReadAllText($cur) }
        catch { return New-Decision 'Keep' "file exists but could not be read ($($_.Exception.Message)); use -Force to replace" -Level 'WARN' }
        # One of our own merged bundles: re-merge from its source (picks up CA rotation and
        # changes the user made to their own bundle).
        if ($text -match '(?m)^# netskope-merged-from: (.+?)\r?$') {
            $src = $Matches[1].Trim()
            if (Test-Path -LiteralPath $src -PathType Leaf) { return New-Decision 'Merge' "value is a merged bundle created by this script; re-checked against its source '$src'" $src }
            return New-Decision 'Set' "value is a merged bundle created by this script, but its source '$src' no longer exists"
        }
    }
    # Earlier Netskope deployments (interactive script, client folder, other directory).
    $leaf = Split-Path -Leaf $cur
    if ($cur -match '(?i)[\\/]netskope[\\/]') { return New-Decision 'Set' 'value is a previous Netskope bundle location (path contains a "netskope" folder)' }
    if ($leaf -match '(?i)^(netskope|nscacert|nstenantcert)') { return New-Decision 'Set' "value is a previous Netskope bundle (file name '$leaf')" }
    if ($isDir)       { return New-Decision 'Keep' 'value is a directory - it cannot be inspected or merged; use -Force to replace' -Level 'WARN' }
    if (-not $isFile) {
        if ($cur -notmatch '[\\/]') { return New-Decision 'Set' 'value is not a file path' }
        return New-Decision 'Set' 'file does not exist'
    }

    $bodies = @(Get-CertBodies $text)
    if ($bodies.Count -eq 0) { return New-Decision 'Set' "file contains no PEM certificates ($((Get-Item -LiteralPath $cur).Length) bytes)" }
    if ($nsBodies.Count -eq 0) {
        return New-Decision 'Keep' "custom bundle with $($bodies.Count) certificate(s); cannot check it for the Netskope CA because the deployed bundle has no netskope-cert-count header (use -Force to replace)" -Level 'WARN'
    }
    $present = @($nsBodies | Where-Object { $bodies -contains $_ }).Count
    if ($present -eq $nsBodies.Count) {
        return New-Decision 'Keep' "custom bundle with $($bodies.Count) certificate(s) that already includes all $($nsBodies.Count) Netskope CA certificate(s)"
    }
    return New-Decision 'Merge' "custom bundle with $($bodies.Count) certificate(s) includes only $present of $($nsBodies.Count) Netskope CA certificate(s)" $cur
}

# Writes <mergeDir>\merged-<hash>.pem = source certs + Netskope CA. One file per source path,
# so several variables pointing at the same custom bundle share it.
function Update-MergedBundle([string]$Source) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-NormPath $Source))) | Select-Object -First 6 | ForEach-Object { $_.ToString('x2') })
    $path = Join-Path $script:mergeDir "merged-$hash.pem"
    $srcText = ([System.IO.File]::ReadAllText($Source) -replace "`r`n", "`n").TrimEnd()
    $content = "# netskope-ssl-configure merged bundle - regenerated on every run, do not edit`n" +
               "# netskope-merged-from: $Source`n" + $srcText + "`n" + ($nsBlocks -join "`n") + "`n"
    $changed = -not ((Test-Path -LiteralPath $path) -and [System.IO.File]::ReadAllText($path) -eq $content)
    if ($changed -and -not $DryRun) {
        if (-not (Test-Path -LiteralPath $script:mergeDir)) { New-Item -ItemType Directory -Path $script:mergeDir -Force | Out-Null }
        [System.IO.File]::WriteAllText("$path.tmp", $content, $utf8NoBom)
        Move-Item -LiteralPath "$path.tmp" -Destination $path -Force
    }
    $summary = "$(@(Get-CertBodies $srcText).Count) from the source + $($nsBlocks.Count) Netskope CA"
    return [pscustomobject]@{ Path = $path; Changed = $changed; Summary = $summary }
}

# Runs the decision for one value. Logs "no change" outcomes itself; returns the new value
# (+ an explanation) to write, or $null for "leave".
#   $Where: scope label (Machine / User / User[jdoe] / Git[...]); $From: where the current
#   value was read, when that adds information.
function Resolve-Value([string]$Name, [string]$Tools, [string]$Current, [string]$Where, [string]$From) {
    $d = Get-Decision $Current
    $cv = Format-Value $Current
    $fromTxt = if ($From) { " (read from $From)" } else { '' }
    switch ($d.Action) {
        'Skip' { Write-Log SKIP "$Where ${Name}: no change - $($d.Reason): $cv$fromTxt [$Tools]"; return $null }
        'Keep' { Write-Log $d.Level "$Where ${Name}: no change - kept existing value $cv$fromTxt - $($d.Reason) [$Tools]"; return $null }
        'Set'  {
            $note = if ($Current) { "$($d.Reason); previous value $cv$fromTxt" } else { "$($d.Reason)$fromTxt" }
            return [pscustomobject]@{ Value = $bundlePath; Note = $note }
        }
        'Merge' {
            $m = Update-MergedBundle $d.Source
            if (Test-SamePath $m.Path $Current) {
                if ($m.Changed) {
                    $verb = if ($DryRun) { 'DRY-RUN would refresh' } else { 'refreshed' }
                    Write-Log OK "$Where ${Name}: merged bundle $verb $(Format-Value $m.Path) because its source '$($d.Source)' or the Netskope CA changed (now $($m.Summary) certificate(s)) [$Tools]"
                } else {
                    Write-Log SKIP "$Where ${Name}: no change - merged bundle $cv is up to date with its source '$($d.Source)' ($($m.Summary) certificate(s)) [$Tools]"
                }
                return $null
            }
            return [pscustomobject]@{ Value = $m.Path; Note = "$($d.Reason); merged into a new bundle ($($m.Summary) certificate(s)) so its other CAs keep working; previous value $cv$fromTxt" }
        }
    }
}

# ============================================================
# Step 2: environment variables (configured regardless of install state)
# ============================================================
# Name, then the tools that read it (informational; used in the log).
$envVars = @(
    @('SSL_CERT_FILE',                        'OpenSSL, Ruby, Go, Terraform, Python ssl/httpx, Netskope CLI'),
    @('CURL_CA_BUNDLE',                       'cURL, Netskope CLI'),
    @('REQUESTS_CA_BUNDLE',                   'Python Requests, Azure CLI, Poetry, Netskope CLI'),
    @('AWS_CA_BUNDLE',                        'AWS CLI'),
    @('NODE_EXTRA_CA_CERTS',                  'Node.js, Claude CLI/Desktop, Bun, VS Code/Cursor'),
    @('npm_config_cafile',                    'npm, Yarn 1'),
    @('YARN_HTTPS_CA_FILE_PATH',              'Yarn 2+'),
    @('PIP_CERT',                             'pip'),
    @('GIT_SSL_CAINFO',                       'Git'),
    @('CARGO_HTTP_CAINFO',                    'Cargo'),
    @('OCI_CLI_CA_BUNDLE',                    'Oracle Cloud CLI'),
    @('CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',   'Google Cloud CLI'),
    @('GRPC_DEFAULT_SSL_ROOTS_FILE_PATH',     'gRPC clients (gcloud, Python grpc)'),
    @('COMPOSER_CAFILE',                      'PHP Composer'),
    @('DENO_CERT',                            'Deno'),
    @('CONDA_SSL_VERIFY',                     'conda'),
    @('NETSKOPE_CA_BUNDLE',                   'Netskope CLI (ntsk)')
)

$profiles = @(Get-TargetProfiles)
Write-Log INFO ("Profiles in scope: {0}" -f (($profiles | ForEach-Object { "$($_.Path) [$($_.Sid)]" }) -join '; '))

function Set-ScopedEnv([string]$Name, [string]$Tools, [string]$Value, [string]$Target, [string]$Note) {
    if ($DryRun) { Write-Log INFO "DRY-RUN would set $Target $Name = '$Value' - $Note [$Tools]"; return }
    try {
        [Environment]::SetEnvironmentVariable($Name, $Value, $Target)
        Write-Log OK "$Target ${Name}: set to '$Value' - $Note [$Tools]"
    } catch { Write-Log ERROR "$Target ${Name}: could not set - $($_.Exception.Message)" }
}

if ($envTarget -eq 'User') {
    # ---- Non-elevated: decide on the value the user actually gets (user, else machine) ----
    Write-Log INFO '--- Environment variables (User scope; checks the effective value = user value, else machine value) ---'
    foreach ($ev in $envVars) {
        $name = $ev[0]; $tools = $ev[1]
        try {
            $userVal    = [Environment]::GetEnvironmentVariable($name, 'User')
            $machineVal = [Environment]::GetEnvironmentVariable($name, 'Machine')
            if ($userVal)        { $effective = $userVal;    $from = 'User scope' }
            elseif ($machineVal) { $effective = $machineVal; $from = 'Machine scope; no User value' }
            else                 { $effective = $null;       $from = 'neither User nor Machine scope' }
            $r = Resolve-Value $name $tools $effective 'User' $from
            if (-not $r) { continue }
            if ($userVal -and (Test-SamePath $r.Value $bundlePath) -and (Test-SamePath $machineVal $bundlePath)) {
                # A stale user override hides a correct machine value: drop the override.
                $msg = "User override removed so the correct Machine value '$machineVal' applies - $($r.Note)"
                if ($DryRun) { Write-Log INFO "DRY-RUN would remove User ${name}: $msg [$tools]"; continue }
                [Environment]::SetEnvironmentVariable($name, $null, 'User')
                Write-Log OK "User ${name}: $msg [$tools]"
            } else {
                Set-ScopedEnv $name $tools $r.Value 'User' $r.Note
            }
        } catch { Write-Log ERROR "User ${name}: $($_.Exception.Message)" }
    }
} else {
    # ---- Elevated (or Process test scope): the machine/process value itself ----
    Write-Log INFO "--- Environment variables ($envTarget scope) ---"
    $finalValue = @{}
    foreach ($ev in $envVars) {
        $name = $ev[0]; $tools = $ev[1]
        try {
            $cur = [Environment]::GetEnvironmentVariable($name, $envTarget)
            $finalValue[$name] = $cur
            $r = Resolve-Value $name $tools $cur $envTarget $null
            if (-not $r) { continue }
            Set-ScopedEnv $name $tools $r.Value $envTarget $r.Note
            $finalValue[$name] = $r.Value
        } catch { Write-Log ERROR "$envTarget ${name}: $($_.Exception.Message)" }
    }

    # ---- Per-user overrides: a user-scope value beats the machine value at runtime ----
    if ($envTarget -eq 'Machine') {
        Write-Log INFO "--- Per-user environment overrides ($($profiles.Count) profile(s); a per-user value beats the machine value) ---"
        foreach ($p in $profiles) {
            $uname    = Split-Path -Leaf $p.Path
            $loaded   = Test-Path -LiteralPath "Registry::HKEY_USERS\$($p.Sid)"
            $hiveName = if ($loaded) { $p.Sid } else { "NSCFG_$($p.Sid)" }
            $ntuser   = Join-Path $p.Path 'NTUSER.DAT'
            if (-not $loaded) {
                if (-not (Test-Path -LiteralPath $ntuser)) { Write-Log SKIP "User[$uname]: no NTUSER.DAT in $($p.Path) - profile never fully created, nothing to check"; continue }
                & reg.exe load "HKU\$hiveName" $ntuser 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Log WARN "User[$uname]: could not load registry hive $ntuser (in use?) - per-user overrides not checked this run"; continue }
            }
            $hiveState = if ($loaded) { 'user logged on, hive already loaded' } else { 'hive loaded from NTUSER.DAT' }
            $key = $null
            try {
                $key = [Microsoft.Win32.Registry]::Users.OpenSubKey("$hiveName\Environment", $true)
                if (-not $key) { Write-Log SKIP "User[$uname]: no per-user Environment key ($hiveState) - machine values apply"; continue }
                $overrides = @()
                foreach ($ev in $envVars) {
                    $name = $ev[0]; $tools = $ev[1]
                    $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if ($null -eq $raw -or "$raw" -eq '') { continue }
                    $overrides += $name
                    # Expand %USERPROFILE% & co. for THAT user, not for SYSTEM.
                    $val = "$raw" -ireplace '%USERPROFILE%', $p.Path `
                                  -ireplace '%APPDATA%', (Join-Path $p.Path 'AppData\Roaming') `
                                  -ireplace '%LOCALAPPDATA%', (Join-Path $p.Path 'AppData\Local')
                    $val = [Environment]::ExpandEnvironmentVariables($val)
                    $from = "HKU\$($p.Sid)\Environment" + $(if ("$raw" -ne $val) { ", raw '$raw'" } else { '' })
                    $where = "User[$uname]"
                    $r = Resolve-Value $name $tools $val $where $from
                    if (-not $r) { continue }
                    try {
                        if ((Test-SamePath $r.Value $bundlePath) -and (Test-SamePath $finalValue[$name] $bundlePath)) {
                            $msg = "per-user override removed so the Machine value '$($finalValue[$name])' applies at next logon - $($r.Note)"
                            if ($DryRun) { Write-Log INFO "DRY-RUN would remove $where ${name}: $msg [$tools]"; continue }
                            $key.DeleteValue($name)
                            Write-Log OK "$where ${name}: $msg [$tools]"
                        } else {
                            $msg = "set to '$($r.Value)' (applies at next logon) - $($r.Note)"
                            if ($DryRun) { Write-Log INFO "DRY-RUN would update $where ${name}: $msg [$tools]"; continue }
                            $key.SetValue($name, $r.Value, [Microsoft.Win32.RegistryValueKind]::String)
                            Write-Log OK "$where ${name}: $msg [$tools]"
                        }
                    } catch { Write-Log ERROR "$where ${name}: $($_.Exception.Message)" }
                }
                if ($overrides.Count -eq 0) { Write-Log SKIP "User[$uname]: no per-user values for these variables ($hiveState) - machine values apply" }
                else { Write-Log INFO "User[$uname]: checked $($overrides.Count) per-user value(s) ($hiveState): $($overrides -join ', ')" }
            } catch {
                Write-Log ERROR "User[$uname]: $($_.Exception.Message)"
            } finally {
                if ($key) { $key.Close() }
                if (-not $loaded) {
                    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
                    & reg.exe unload "HKU\$hiveName" 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { Write-Log WARN "User[$uname]: registry hive could not be unloaded (HKU\$hiveName)" }
                }
            }
        }
    }
}

# Informational: which tools can this process see, and where? (Under SYSTEM this reflects the
# system PATH only, so "not found" does not prove a tool is absent from a user's profile.)
$probe = @('python', 'pip', 'aws', 'az', 'node', 'npm', 'yarn', 'git', 'gcloud', 'curl', 'openssl',
           'cargo', 'ruby', 'composer', 'oci', 'claude', 'ntsk', 'docker')
$found = @(); $missing = @()
foreach ($t in $probe) {
    $c = Get-Command $t -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $found += "$t=$($c.Source)" } else { $missing += $t }
}
Write-Log INFO ("Tools on PATH of this process: {0}" -f ($(if ($found) { $found -join '; ' } else { '(none)' })))
Write-Log INFO ("Tools not on PATH (env vars are still configured for future installs): {0}" -f ($(if ($missing) { $missing -join ', ' } else { '(none)' })))

# ============================================================
# Step 3: file / directory based configuration
# ============================================================
Write-Log INFO "--- File-based configuration ($($profiles.Count) profile(s)) ---"

# --- Git ---
# Same rule as the env vars: a custom http.sslCAInfo is only replaced when it is stale or
# lacks the Netskope CA (then merged), never blindly.
$git = Find-Exe @('git') @("$env:ProgramFiles\Git\cmd\git.exe", "${env:ProgramFiles(x86)}\Git\cmd\git.exe")
if (-not $git) {
    Write-Log SKIP 'Git: not installed (git.exe not on PATH or in Program Files\Git) - skipped .gitconfig update; GIT_SSL_CAINFO is still configured'
} else {
    Write-Log INFO "Git: using $git"
    foreach ($p in $profiles) {
        $cfg = Join-Path $p.Path '.gitconfig'
        try {
            $cur = (& $git config --file $cfg --get http.sslCAInfo 2>$null)
            if ($cur) { $cur = "$cur".Trim() }
            $from = if (Test-Path -LiteralPath $cfg) { $cfg } else { "$cfg - file does not exist yet" }
            $r = Resolve-Value 'http.sslCAInfo' 'Git' $cur 'Git' $from
            if (-not $r) { continue }
            $val = $r.Value -replace '\\', '/'   # git parses backslashes as escapes
            if ($DryRun) { Write-Log INFO "DRY-RUN would set Git http.sslCAInfo = '$val' in $cfg - $($r.Note)"; continue }
            & $git config --file $cfg http.sslCAInfo $val
            if ($LASTEXITCODE -ne 0) { throw "git exited $LASTEXITCODE" }
            Write-Log OK "Git http.sslCAInfo: set to '$val' in $cfg - $($r.Note)"
        } catch { Write-Log ERROR "Git: $cfg : $($_.Exception.Message)" }
    }
}

# --- Azure Storage Explorer (reads extra certs from its own certs\ directory) ---
foreach ($p in $profiles) {
    $certsDir = Join-Path $p.Path 'AppData\Local\Programs\Microsoft Azure Storage Explorer\certs'
    if (-not (Test-Path -LiteralPath $certsDir)) {
        Write-Log SKIP "Azure Storage Explorer: not installed for $($p.Path) (no $certsDir) - skipped"
        continue
    }
    try {
        $target = Join-Path $certsDir $CertName
        $bh = Get-ShortHash $bundlePath
        $th = if (Test-Path -LiteralPath $target) { Get-ShortHash $target } else { $null }
        if ($th -eq $bh) { Write-Log SKIP "Azure Storage Explorer: no change - $target is identical to the bundle (SHA256 $bh...)"; continue }
        $why = if ($th) { "replacing an outdated copy (SHA256 $th... -> $bh...)" } else { 'first copy' }
        if ($DryRun) { Write-Log INFO "DRY-RUN would copy bundle to $target ($why)"; continue }
        Copy-Item -LiteralPath $bundlePath -Destination $target -Force
        Write-Log OK "Azure Storage Explorer: bundle copied to $target ($why)"
    } catch { Write-Log ERROR "Azure Storage Explorer: $certsDir : $($_.Exception.Message)" }
}

# ============================================================
# Done
# ============================================================
$secs = [Math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)
Write-Log INFO ("Summary: {0} changed (OK), {1} unchanged (SKIP), {2} warning(s), {3} error(s) in {4}s" -f $script:Counts.OK, $script:Counts.SKIP, $script:Counts.WARN, $script:Counts.ERROR, $secs)
if ($script:Counts.ERROR -gt 0) {
    Write-Log WARN "===== finished with $($script:Counts.ERROR) error(s) - see lines marked ERROR ====="
    exit 2
}
Write-Log INFO '===== finished OK (new processes/logons pick up env changes; running apps do not) ====='
exit 0
