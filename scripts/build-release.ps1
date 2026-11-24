<#
.SYNOPSIS
    Builds the Whereabouts installer and its checksums.

.DESCRIPTION
    1. Downloads the offline data files if they are missing (see data/README.md).
    2. Builds the background service in release mode.
    3. Places it where the installer bundles it, next to the desktop app.
    4. Checks and builds the web UI, then the app and its NSIS installer.
    5. Copies the installer to target\dist and writes SHA256SUMS.txt.

    Code signing (optional): with a code-signing certificate in the Windows
    certificate store, pass its thumbprint (or set
    WHEREABOUTS_SIGN_THUMBPRINT). The service is signed with signtool, and
    Tauri signs the app, its uninstaller and the installer; the build fails if
    any of them is not signed with that certificate. Without a thumbprint the
    build is unsigned, and says so.

    The installer installs to C:\Program Files\Whereabouts (for all users,
    needs administrator rights), registers the background service and
    starts it. Uninstalling stops and removes the service and asks whether
    to delete the saved history.

.PARAMETER RefreshData
    Download the offline data files again even if they are present.

.PARAMETER SignThumbprint
    SHA-1 thumbprint of the code-signing certificate to sign with (default:
    the WHEREABOUTS_SIGN_THUMBPRINT environment variable; empty: unsigned).

.PARAMETER TimestampUrl
    RFC 3161 timestamp server, so signatures stay valid after the
    certificate expires (default: WHEREABOUTS_SIGN_TIMESTAMP_URL, else
    DigiCert's public server).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
#>
[CmdletBinding()]
param(
    [switch]$RefreshData,
    [string]$SignThumbprint = $env:WHEREABOUTS_SIGN_THUMBPRINT,
    [string]$TimestampUrl = $env:WHEREABOUTS_SIGN_TIMESTAMP_URL
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $Cargo)) { $Cargo = 'cargo' }
# SQLCipher's OpenSSL build needs a native Windows Perl (Strawberry Perl).
$StrawberryPerl = 'C:\Strawberry\perl\bin\perl.exe'
if (Test-Path $StrawberryPerl) { $env:OPENSSL_SRC_PERL = $StrawberryPerl }

if (-not $TimestampUrl) { $TimestampUrl = 'http://timestamp.digicert.com' }
$Signing = [bool]$SignThumbprint
if ($Signing) {
    $SignThumbprint = ($SignThumbprint -replace '\s', '').ToUpperInvariant()
    if ($SignThumbprint -notmatch '^[0-9A-F]{40}$') { throw 'SignThumbprint must be a 40-character SHA-1 thumbprint' }
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $SignTool) { throw 'signtool.exe was not found; install the Windows SDK' }
}

# Throws unless the file carries an Authenticode signature by the chosen
# certificate (a test certificate may be untrusted; the signer is what counts).
function Assert-Signed {
    param([string]$Path)
    $signature = Get-AuthenticodeSignature $Path
    if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $SignThumbprint) {
        throw "$Path is not signed with certificate $SignThumbprint ($($signature.Status))"
    }
    Write-Host "  signed: $Path ($($signature.Status))"
}

function Invoke-Step {
    param([string]$Title, [scriptblock]$Action)
    Write-Host "==> $Title" -ForegroundColor Cyan
    & $Action
    if ($LASTEXITCODE -ne 0) { throw "$Title failed (exit code $LASTEXITCODE)" }
}

Push-Location $RepoRoot
try {
    $data = 'easyprivacy.txt', 'dbip-country-lite.mmdb', 'dbip-asn-lite.mmdb', 'SOURCES.generated.txt'
    $missing = @($data | Where-Object { -not (Test-Path (Join-Path 'data' $_)) })
    if ($RefreshData -or $missing.Count -gt 0) {
        Invoke-Step 'Download offline data' { & powershell -NoProfile -ExecutionPolicy Bypass -File scripts\update-data.ps1 }
    }

    Invoke-Step 'Build the service (release)' { & $Cargo build --release --locked -p whereabouts-service }

    # Tauri bundles extra programs named after the target, e.g.
    # whereabouts-service-x86_64-pc-windows-msvc.exe, and installs them
    # under their plain name next to the app.
    $triple = ((& rustc -vV) | Select-String '^host: (.+)$').Matches[0].Groups[1].Value
    $binaries = Join-Path $RepoRoot 'ui\src-tauri\binaries'
    New-Item -ItemType Directory -Force -Path $binaries | Out-Null
    if ($Signing) {
        Invoke-Step 'Sign the service' {
            & $SignTool.FullName sign /sha1 $SignThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 'target\release\whereabouts-service.exe'
        }
    }
    Copy-Item 'target\release\whereabouts-service.exe' (Join-Path $binaries "whereabouts-service-$triple.exe") -Force

    Push-Location ui
    try {
        Invoke-Step 'Install UI dependencies' { & npm ci --no-fund --no-audit }
        Invoke-Step 'Check the UI' { & npm run check }
        $configs = @('--config', 'src-tauri/tauri.installer.json')
        if ($Signing) {
            # Tauri signs the app, the uninstaller and the installer itself.
            $signConfig = @{ bundle = @{ windows = @{
                certificateThumbprint = $SignThumbprint
                digestAlgorithm = 'sha256'
                timestampUrl = $TimestampUrl
            } } } | ConvertTo-Json -Depth 4 -Compress
            $configs += @('--config', $signConfig)
        }
        Invoke-Step 'Build the app and installer' {
            & npx tauri build @configs -- --locked
        }
    } finally {
        Pop-Location
    }

    $installer = Get-ChildItem 'target\release\bundle\nsis\*-setup.exe' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $installer) { throw 'the installer was not found in target\release\bundle\nsis' }
    if ($Signing) {
        Write-Host '==> Check the signatures' -ForegroundColor Cyan
        Assert-Signed 'target\release\whereabouts-service.exe'
        Assert-Signed 'target\release\whereabouts.exe'
        Assert-Signed $installer.FullName
    } else {
        Write-Warning 'This build is NOT code-signed: Windows SmartScreen will warn, and Whereabouts lists itself as UNSIGNED. Pass -SignThumbprint to sign it.'
    }
    $dist = Join-Path $RepoRoot 'target\dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    Get-ChildItem $dist | Remove-Item -Force
    Copy-Item $installer.FullName $dist
    $sums = Get-ChildItem $dist -File | Where-Object Name -ne 'SHA256SUMS.txt' | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
    }
    Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $sums -Encoding ascii
    Write-Host ''
    Write-Host "Installer: $(Join-Path $dist $installer.Name)" -ForegroundColor Green
    Get-Content (Join-Path $dist 'SHA256SUMS.txt')
} finally {
    Pop-Location
}
