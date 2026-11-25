<#
.SYNOPSIS
    Captures one lab session: the Whereabouts engine records while a persona
    uses real apps (logged out), then the flows are exported.

.DESCRIPTION
    Lab only, for GitHub's disposable Windows runners (never a real user's PC):
    it needs administrator rights and deletes C:\ProgramData\Whereabouts.

    Writes to -Out:
      session.csv   the engine's CSV export (whereabouts-service --export)
      connections.jsonl  when each connection was opened (the engine's
                    lab-only --record-connections), for beaconing
      session.json  metadata: persona, times, runner, apps and versions,
                    health counters over time, live-scenario labels
      engine.log    the engine's console output

    With -LiveScenarios it also stages, inside the session:
      renamed_binary  a copy of curl.exe named Discord.exe in a user folder
                      fetches https://www.wikipedia.org/ (a program posing as
                      a popular app)
      known_bad       curl.exe fetches https://example.com/; the analysis lists
                      example.com's addresses (recorded here) as a test entry
                      in its DROP list. Nothing risky is contacted.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('office', 'media', 'gamer', 'developer')][string]$Persona,
    [Parameter(Mandatory)][double]$Minutes,
    [Parameter(Mandatory)][string]$SessionId,
    [Parameter(Mandatory)][string]$Out,
    [Parameter(Mandatory)][string]$Service,
    [int]$Seed = 1,
    [switch]$LiveScenarios
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This script deletes C:\ProgramData\Whereabouts (saved history included)
# and installs apps: it must never run on a real computer.
if ($env:GITHUB_ACTIONS -ne 'true') {
    Write-Host 'run-session.ps1 deletes Whereabouts'' saved data and installs apps, so it runs only on'
    Write-Host 'GitHub''s disposable runners (GITHUB_ACTIONS=true). Nothing was changed.'
    exit 2
}

$LabRoot = Split-Path -Parent $PSScriptRoot
$InstallTimeoutSeconds = 600
$DataHome = Join-Path $env:ProgramData 'Whereabouts'

function Get-UnixNow { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Expand-LabPath([string]$Path) { [Environment]::ExpandEnvironmentVariables($Path) }

# Where the app's program is: its usual place, or a second one (per-user installs).
function Get-AppExe([hashtable]$App) {
    $places = @($App.exe) + @(if ($App.ContainsKey('exe_alt')) { $App.exe_alt })
    foreach ($place in $places) {
        $path = Expand-LabPath $place
        if (Test-Path $path) { return $path }
    }
    Expand-LabPath $App.exe
}

function Get-AppRecord([string]$Id, [hashtable]$App, [bool]$Installed, [string]$Via) {
    $exe = Get-AppExe $App
    $present = Test-Path $exe
    [ordered]@{
        id        = $Id
        name      = $App.name
        installed = $Installed -and $present
        via       = $Via
        path      = if ($present) { $exe } else { $null }
        version   = if ($present) { (Get-Item $exe).VersionInfo.ProductVersion } else { $null }
        sha256    = if ($present) { (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    }
}

# Runs an installer, stopping it if it takes longer than the time limit.
function Invoke-Installer([string]$Program, [string[]]$Arguments) {
    $process = Start-Process -FilePath $Program -ArgumentList $Arguments -NoNewWindow -PassThru
    if (-not $process.WaitForExit($InstallTimeoutSeconds * 1000)) {
        Write-Warning "$Program took longer than $InstallTimeoutSeconds s; stopping it"
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}

# Installs one app (winget, else Chocolatey, both preinstalled on GitHub's
# runners or one of them). A failure is recorded, never fatal.
function Install-LabApp([string]$Id) {
    $apps = Get-Content (Join-Path $PSScriptRoot 'apps.json') -Raw | ConvertFrom-Json -AsHashtable
    $app = $apps[$Id]
    if (Test-Path (Get-AppExe $app)) { return Get-AppRecord $Id $app $true 'preinstalled' }
    $via = 'none'
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $via = 'winget'
            Invoke-Installer 'winget' @('install', '--id', $app.winget, '--exact', '--silent',
                '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
        }
        if (-not (Test-Path (Get-AppExe $app)) -and (Get-Command choco -ErrorAction SilentlyContinue)) {
            $via = 'choco'
            Invoke-Installer 'choco' @('install', $app.choco, '-y', '--no-progress')
        }
    } catch {
        Write-Warning "installing $Id failed: $_"
    }
    Get-AppRecord $Id $app $true $via
}

function Start-LabApp([hashtable]$Record) {
    if (-not $Record.installed) { return }
    $apps = Get-Content (Join-Path $PSScriptRoot 'apps.json') -Raw | ConvertFrom-Json -AsHashtable
    $app = $apps[$Record.id]
    $startArgs = if ($app.ContainsKey('start_args')) { $app.start_args } else { '' }
    try {
        if ($startArgs) { Start-Process -FilePath $Record.path -ArgumentList $startArgs | Out-Null }
        else { Start-Process -FilePath $Record.path | Out-Null }
    } catch {
        Write-Warning "starting $($Record.id) failed: $_"
    }
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
if (Test-Path $DataHome) { Remove-Item -Recurse -Force $DataHome }

$session = [ordered]@{
    schema        = 1
    id            = $SessionId
    persona       = $Persona
    ok            = $false
    error         = $null
    start         = $null
    end           = $null
    runner_image  = "$env:ImageOS $env:ImageVersion".Trim()
    engine_commit = $env:GITHUB_SHA
    seed          = $Seed
    apps          = @()
    counters      = @()
    live          = @()
}
$engine = $null
$sampler = $null
$countersFile = Join-Path $Out 'counters.jsonl'
$csv = Join-Path $Out 'session.csv'
$connectionsFile = Join-Path $Out 'connections.jsonl'
$engineSeconds = [int]($Minutes * 60) + 120

# Whatever happens, session.json is written (ok = false with the error, so
# the analysis lists the session as skipped) and the engine is stopped.
try {
    # 1. Apps for this persona (before capture, so installers are not recorded).
    $personaScript = Join-Path $PSScriptRoot "personas\$Persona.ps1"
    $session.apps = @(& $personaScript -Install -LabRoot $LabRoot)

    # 2. The engine records for the whole session, and (lab only) when each
    #    connection was opened, for beaconing.
    $engine = Start-Process -FilePath $Service `
        -ArgumentList '--console', '--seconds', $engineSeconds, '--record-connections', "`"$connectionsFile`"" `
        -RedirectStandardOutput (Join-Path $Out 'engine.log') -RedirectStandardError (Join-Path $Out 'engine.err.log') `
        -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 15
    if ($engine.HasExited) { throw "the engine stopped at once (exit code $($engine.ExitCode)); see engine.log" }
    $session.start = Get-UnixNow

    # 3. Health counters every 10 seconds while the engine runs.
    $sampler = Start-Job -ArgumentList $Service, $countersFile, $engine.Id -ScriptBlock {
        param($service, $file, $enginePid)
        while (Get-Process -Id $enginePid -ErrorAction SilentlyContinue) {
            $line = & $service --status --json 2>$null
            if ($LASTEXITCODE -eq 0 -and $line) {
                $status = $line | ConvertFrom-Json
                $sample = [ordered]@{
                    time         = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    rejected     = $status.rejected
                    unattributed = $status.unattributed
                }
                ($sample | ConvertTo-Json -Compress) | Add-Content -Path $file
            }
            Start-Sleep -Seconds 10
        }
    }

    # 4. The persona uses its apps.
    & $personaScript -Run -LabRoot $LabRoot -Minutes $Minutes -Seed $Seed -Apps $session.apps

    # 5. Live scenarios (while the engine still records).
    if ($LiveScenarios) {
        if ($engine.HasExited) { throw 'the engine stopped before the live scenarios' }
        $curl = Join-Path $env:SystemRoot 'System32\curl.exe'

        $fake = Join-Path $env:LOCALAPPDATA 'Lab\Discord.exe'
        New-Item -ItemType Directory -Force -Path (Split-Path $fake) | Out-Null
        Copy-Item $curl $fake -Force
        $from = Get-UnixNow
        1..3 | ForEach-Object { & $fake -s -o NUL https://www.wikipedia.org/; Start-Sleep -Seconds 3 }
        $session.live += [ordered]@{
            scenario = "$SessionId-renamed"; type = 'renamed_binary'; app_name = 'Discord.exe'
            app_path = $fake; start = $from; end = Get-UnixNow
        }

        $addresses = @(Resolve-DnsName example.com -Type A_AAAA -ErrorAction SilentlyContinue |
                Where-Object { $_.PSObject.Properties['IPAddress'] } | ForEach-Object { $_.IPAddress })
        $from = Get-UnixNow
        1..3 | ForEach-Object { & $curl -s -o NUL https://example.com/; Start-Sleep -Seconds 3 }
        $session.live += [ordered]@{
            scenario = "$SessionId-knownbad"; type = 'known_bad'; app_name = 'curl.exe'
            app_path = $curl; start = $from; end = Get-UnixNow; addresses = $addresses
        }
    }
    $session.end = Get-UnixNow

    # 6. Let the engine finish and save.
    if (-not $engine.WaitForExit(($engineSeconds + 120) * 1000)) {
        throw 'the engine did not stop by itself in time'
    }
} catch {
    $session.error = "$_"
    Write-Warning "session $SessionId failed: $_"
} finally {
    if ($sampler) {
        Stop-Job $sampler -ErrorAction SilentlyContinue
        Remove-Job $sampler -Force -ErrorAction SilentlyContinue
    }
    if ($engine -and -not $engine.HasExited) {
        Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    if (-not $session.end) { $session.end = Get-UnixNow }
    if (-not $session.start) { $session.start = $session.end }
    try { & $Service --export $csv | Out-Host } catch { Write-Warning "export failed: $_" }
    $rows = @(Get-Content $csv -ErrorAction SilentlyContinue).Count - 1
    $session.ok = ($rows -ge 1) -and -not $session.error
    if (Test-Path $countersFile) {
        $session.counters = @(Get-Content $countersFile | ForEach-Object { $_ | ConvertFrom-Json })
    }
    $session | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $Out 'session.json') -Encoding utf8
    Remove-Item -Recurse -Force $DataHome -ErrorAction SilentlyContinue
    $failed = if ($session.error) { ", error: $($session.error)" } else { '' }
    Write-Host "session $SessionId ($Persona): $rows flows, ok=$($session.ok)$failed"
}
