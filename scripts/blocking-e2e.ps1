<#
.SYNOPSIS
  Blocking end to end: runs the Whereabouts engine in console mode, adds and
  removes rules with the command line, and checks with a copy of curl that
  they really block and unblock.

.DESCRIPTION
  Needs administrator rights, internet access, and no Whereabouts service
  running (two engines cannot run at once). Only a copy of curl is ever
  blocked. At the end every rule is removed and Whereabouts' entries are
  removed from the Windows firewall. Used by CI's live job.

.PARAMETER Exe
  The whereabouts-service.exe to test (default: the debug build).
#>
param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\target\debug\whereabouts-service.exe')
)

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this as administrator.' }
$installed = Get-Service -Name Whereabouts -ErrorAction SilentlyContinue
if ($installed -and $installed.Status -ne 'Stopped') {
    throw 'The Whereabouts service is running; this test needs to run its own engine.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) "whereabouts-e2e-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
$curl = Join-Path $work 'curl-e2e.exe'
Copy-Item (Join-Path $env:SystemRoot 'System32\curl.exe') $curl
$log = Join-Path $work 'console.log'
$failures = 0

function Invoke-Wa([string[]]$Arguments) {
    # Error output is part of the answer, not a script error.
    $ErrorActionPreference = 'Continue'
    $text = & $Exe @Arguments 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
}

function Test-Reach([string]$Program, [string[]]$Extra = @(), [string]$Url = 'https://example.com/') {
    $ErrorActionPreference = 'Continue'
    & $Program --silent --output NUL --max-time 8 @Extra $Url 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Wait-Until([scriptblock]$Condition, [int]$Seconds = 20) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Check([bool]$Ok, [string]$What) {
    if ($Ok) {
        Write-Host "  ok    $What"
    } else {
        Write-Host "  FAIL  $What" -ForegroundColor Red
        $script:failures++
    }
}

function Add-Rule([string[]]$Arguments) {
    $result = Invoke-Wa $Arguments
    if ($result.Code -ne 0 -or $result.Text -notmatch 'Added rule (\d+)\.') {
        throw "adding a rule failed: $($result.Text)"
    }
    return [int]$Matches[1]
}

Write-Host 'Starting the engine in console mode...'
$engine = Start-Process -FilePath $Exe -ArgumentList '--console', '--seconds', '240' `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
try {
    if (-not (Wait-Until { (Invoke-Wa @('--status')).Code -eq 0 } 60)) {
        throw "the engine did not start: $(Get-Content $log, "$log.err" -Raw)"
    }
    # Answers Windows cached before the engine started are never confirmed
    # (an earlier test step looked up example.com), so start from an empty
    # cache: this test checks names looked up while Whereabouts runs.
    Clear-DnsClientCache
    Check (Test-Reach $curl) 'the copy of curl reaches example.com before any rule'

    Write-Host 'App rule'
    $id = Add-Rule @('--block-app', $curl)
    Check (-not (Test-Reach $curl)) 'blocked: the copy of curl cannot connect'
    Check (Test-Reach (Join-Path $env:SystemRoot 'System32\curl.exe')) 'the real curl still connects'
    Check ((Invoke-Wa @('--rules')).Text -match 'curl-e2e\.exe') '--rules lists the rule'
    # The status is refreshed every two seconds.
    Check (Wait-Until { (Invoke-Wa @('--status')).Text -match 'Blocking rules: 1' } 10) '--status counts the rule'
    Check ((Invoke-Wa @('--pause-blocking')).Code -eq 0 -and (Test-Reach $curl)) 'paused: it connects'
    Check ((Invoke-Wa @('--resume-blocking')).Code -eq 0 -and -not (Test-Reach $curl)) 'resumed: blocked again'
    Check ((Invoke-Wa @('--unblock', "$id")).Code -eq 0 -and (Test-Reach $curl)) 'rule removed: it connects'

    Write-Host 'Domain rule (blocked once the DNS service confirms an address)'
    # example.com is in Windows' DNS cache by now, so this also checks that
    # answers confirmed before the rule existed are used.
    $id = Add-Rule @('--block-domain', 'example.com', '--for', $curl)
    Check (Wait-Until { -not (Test-Reach $curl) } 30) 'example.com is blocked for the copy of curl'
    Check (Test-Reach $curl -Url 'https://api.github.com/') 'other domains still connect'
    Check ((Invoke-Wa @('--rules')).Text -match 'example\.com \(([1-9]\d*) addresses now\)') 'the rule shows its learned addresses'
    Check ((Invoke-Wa @('--unblock', "$id")).Code -eq 0 -and (Test-Reach $curl)) 'rule removed: it connects'

    Write-Host 'Address rule'
    $ip = (Resolve-DnsName example.com -Type A | Where-Object IPAddress | Select-Object -First 1).IPAddress
    $pin = @('--resolve', "example.com:443:$ip")
    $id = Add-Rule @('--block-ip', $ip, '--for', $curl)
    Check (-not (Test-Reach $curl $pin)) "$ip is blocked for the copy of curl"
    Check ((Invoke-Wa @('--unblock', "$id")).Code -eq 0 -and (Test-Reach $curl $pin)) 'rule removed: it connects'

    Write-Host 'Refusals'
    Check ((Invoke-Wa @('--block-app', (Join-Path $env:SystemRoot 'System32\svchost.exe'))).Code -ne 0) 'svchost.exe is refused'
    Check ((Invoke-Wa @('--block-ip', '127.0.0.1')).Code -ne 0) 'loopback is refused'
    Check ((Invoke-Wa @('--block-domain', 'localhost')).Code -ne 0) 'a name without a dot is refused'
    Check ((Invoke-Wa @('--rules')).Text -match 'No blocking rules') 'nothing refused was saved'

    Write-Host 'Emergency switch'
    $id = Add-Rule @('--block-app', $curl)
    Check ((Invoke-Wa @('--unblock-all')).Code -eq 0 -and (Test-Reach $curl)) '--unblock-all lifts the block'
    Check ((Invoke-Wa @('--rules')).Text -match 'PAUSED') 'blocking is paused, the rule is kept'
    Invoke-Wa @('--unblock', "$id") | Out-Null
    Invoke-Wa @('--resume-blocking') | Out-Null
} catch {
    Write-Host "  FAIL  $_" -ForegroundColor Red
    $failures++
} finally {
    if (-not $engine.HasExited) { Stop-Process -Id $engine.Id -Force }
    $engineLog = Get-Content $log -Tail 40 -ErrorAction SilentlyContinue
    # Remove Whereabouts' entries from the firewall (no service is installed,
    # so only the blocks and the firewall entries are removed).
    $cleanup = Invoke-Wa @('--unregister', '--remove-blocks')
    if ($cleanup.Code -ne 0) { Write-Host "cleanup: $($cleanup.Text)" -ForegroundColor Red; $failures++ }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($failures -gt 0) {
    Write-Host "$failures check(s) failed. Engine log:"
    $engineLog
    exit 1
}
Write-Host 'ok. Blocking works end to end.'
