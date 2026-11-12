<#
.SYNOPSIS
    Runs the Whereabouts live tests against real Windows ETW events.

.DESCRIPTION
    1. Builds everything as the current user.
    2. Runs the live tests with administrator rights (one UAC prompt):
       - the ignored integration tests in crates/win-capture/tests/live_capture.rs
       - a smoke test of `whereabouts-service --console` while curl.exe downloads a page
    3. Prints PASS or FAIL and exits with 0 on success, 1 on failure.

    The tests make a few HTTPS requests to example.com. Logs, which contain
    this computer's connection metadata, are written to a temporary folder
    and are never committed.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\live-test.ps1
#>
[CmdletBinding()]
param(
    # Internal: set when the script re-runs itself with administrator rights.
    [switch]$Elevated,
    # Internal: folder where the elevated run writes its logs.
    [string]$WorkDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $Cargo)) { $Cargo = 'cargo' }
$ServiceExe = Join-Path $RepoRoot 'target\debug\whereabouts-service.exe'
$TestUrl = 'https://example.com'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param([string]$Text)
    Write-Host $Text
    Add-Content -Path (Join-Path $WorkDir 'live-test.log') -Value $Text -Encoding UTF8
}

# Starts a program with its output redirected to files in $WorkDir.
function Start-Logged {
    param([string]$FilePath, [string[]]$Arguments, [string]$Name)
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
        -WorkingDirectory $RepoRoot -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $WorkDir "$Name.out.txt") `
        -RedirectStandardError (Join-Path $WorkDir "$Name.err.txt")
    # Reading Handle now makes ExitCode available after the process exits.
    $null = $process.Handle
    return $process
}

function Get-LoggedOutput {
    param([string]$Name)
    $text = ''
    foreach ($suffix in 'out', 'err') {
        $path = Join-Path $WorkDir "$Name.$suffix.txt"
        if (Test-Path $path) {
            $content = Get-Content -Path $path -Raw -Encoding UTF8
            if ($content) { $text += $content }
        }
    }
    return $text
}

function Invoke-IntegrationTests {
    Write-Log '--- 1/2  ETW integration tests ---'
    $process = Start-Logged -FilePath $Cargo -Name 'integration' -Arguments @(
        'test', '-p', 'whereabouts-win-capture', '--test', 'live_capture',
        '--', '--ignored', '--test-threads=1')
    if (-not $process.WaitForExit(300000)) {
        $process.Kill()
        Write-Log 'FAIL: integration tests timed out after 5 minutes'
        return $false
    }
    $output = Get-LoggedOutput -Name 'integration'
    $output -split "`r?`n" | Where-Object { $_ -match '^test |test result|panicked|assert' } |
        ForEach-Object { Write-Log "    $_" }
    if ($process.ExitCode -ne 0 -or $output -notmatch 'test result: ok\. 4 passed') {
        Write-Log "FAIL: integration tests (exit code $($process.ExitCode))"
        return $false
    }
    Write-Log 'ok: integration tests'
    return $true
}

function Invoke-ConsoleSmokeTest {
    Write-Log '--- 2/2  Console smoke test ---'
    $console = Start-Logged -FilePath $ServiceExe -Name 'console' -Arguments @(
        '--console', '--seconds', '12')
    Start-Sleep -Seconds 4
    # Empty the DNS cache so curl's lookup is confirmed by the DNS service.
    & ipconfig /flushdns | Out-Null
    $curl = Start-Process -FilePath 'curl.exe' -NoNewWindow -Wait -PassThru -ArgumentList @(
        '--silent', '--output', 'NUL', '--max-time', '15', $TestUrl)
    Write-Log "    curl.exe (pid $($curl.Id)) exited with $($curl.ExitCode)"
    # A renamed copy must still be recognised by its signature.
    $renamedPath = Join-Path $WorkDir 'renamed-tool.exe'
    Copy-Item -Path (Join-Path $env:SystemRoot 'System32\curl.exe') -Destination $renamedPath
    $renamed = Start-Process -FilePath $renamedPath -NoNewWindow -Wait -PassThru -ArgumentList @(
        '--silent', '--output', 'NUL', '--max-time', '15', $TestUrl)
    Write-Log "    renamed-tool.exe (pid $($renamed.Id)) exited with $($renamed.ExitCode)"

    if (-not $console.WaitForExit(60000)) {
        $console.Kill()
        Write-Log 'FAIL: console did not exit within 60 seconds'
        return $false
    }
    $output = Get-LoggedOutput -Name 'console'
    $summaries = @($output -split "`r?`n" | Where-Object { $_ -like '*active flows*' })
    $passed = $true
    if ($console.ExitCode -ne 0) {
        Write-Log "FAIL: console exited with $($console.ExitCode)"
        $passed = $false
    }
    if ($summaries.Count -eq 0) {
        Write-Log 'FAIL: console printed no summary line'
        $passed = $false
    } else {
        $last = $summaries[-1]
        Write-Log "    $last"
        if ($last -notmatch ' 0 unreadable') {
            Write-Log 'FAIL: some events could not be decoded'
            $passed = $false
        }
    }
    $curlRows = @($output -split "`r?`n" | Where-Object { $_ -match "^\s*$($curl.Id)\s+curl\.exe\s" })
    if ($curlRows.Count -eq 0) {
        Write-Log "FAIL: curl.exe (pid $($curl.Id)) is not in the console table"
        $passed = $false
    } else {
        Write-Log "    $($curlRows[-1].Trim())"
        # A verified label has no "?" or "*" marker after the name.
        if ($curlRows[-1] -notmatch '\sexample\.com\s') {
            Write-Log 'FAIL: curl.exe row is not labelled with a verified example.com'
            $passed = $false
        }
        # curl.exe is listed in more than one Microsoft-signed catalog
        # ("Microsoft Windows", "Microsoft 3rd Party Application Component").
        if ($curlRows[-1] -notmatch 'curl\.exe\s+Microsoft ') {
            Write-Log 'FAIL: curl.exe row does not show a Microsoft publisher'
            $passed = $false
        }
    }
    $renamedRows = @($output -split "`r?`n" | Where-Object { $_ -match "^\s*$($renamed.Id)\s+renamed-tool\.exe\s" })
    if ($renamedRows.Count -eq 0) {
        Write-Log "FAIL: renamed-tool.exe (pid $($renamed.Id)) is not in the console table"
        $passed = $false
    } else {
        Write-Log "    $($renamedRows[-1].Trim())"
        if ($renamedRows[-1] -notmatch 'renamed-tool\.exe\s+Microsoft ') {
            Write-Log 'FAIL: the renamed copy of curl.exe is not recognised as Microsoft-signed'
            $passed = $false
        }
    }
    if ($passed) { Write-Log 'ok: console smoke test' }
    return $passed
}

function Invoke-LiveTests {
    $integration = Invoke-IntegrationTests
    $console = Invoke-ConsoleSmokeTest
    return ($integration -and $console)
}

# --- Elevated part -----------------------------------------------------------
if ($Elevated) {
    try {
        if (Invoke-LiveTests) { exit 0 } else { exit 1 }
    } catch {
        Write-Log "FAIL: $_"
        exit 1
    }
}

# --- Normal part -------------------------------------------------------------
$WorkDir = Join-Path ([IO.Path]::GetTempPath()) ("whereabouts-live-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $WorkDir | Out-Null

Write-Host 'Building (as the current user)...'
& $Cargo build -p whereabouts-service
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: build failed'; exit 1 }
& $Cargo test -p whereabouts-win-capture --test live_capture --no-run
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: test build failed'; exit 1 }

if (Test-IsAdministrator) {
    $passed = Invoke-LiveTests
} else {
    Write-Host 'Running live tests as administrator. Please approve the UAC prompt...'
    try {
        $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru `
            -WindowStyle Hidden -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', "`"$PSCommandPath`"", '-Elevated', '-WorkDir', "`"$WorkDir`"")
    } catch {
        Write-Host 'FAIL: administrator rights were not granted (UAC prompt declined?)'
        exit 1
    }
    $log = Join-Path $WorkDir 'live-test.log'
    if (Test-Path $log) { Get-Content -Path $log -Encoding UTF8 | Write-Host }
    $passed = ($child.ExitCode -eq 0)
}

Write-Host ''
Write-Host "Logs: $WorkDir"
if ($passed) {
    Write-Host 'PASS: all live tests passed' -ForegroundColor Green
    exit 0
} else {
    Write-Host 'FAIL: see the messages above' -ForegroundColor Red
    exit 1
}
