<#
.SYNOPSIS
    Captures one lab session: the Whereabouts engine records while a persona
    uses real apps (logged out), then the flows are exported.

.DESCRIPTION
    Lab only, for GitHub's disposable Windows runners (never a real user's PC):
    it needs administrator rights and deletes C:\ProgramData\Whereabouts.

    Writes to -Out:
      session.csv   the engine's CSV export (whereabouts-service --export)
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
$LabRoot = Split-Path -Parent $PSScriptRoot
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
            & winget install --id $app.winget --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Host
        }
        if (-not (Test-Path (Get-AppExe $app)) -and (Get-Command choco -ErrorAction SilentlyContinue)) {
            $via = 'choco'
            & choco install $app.choco -y --no-progress | Out-Host
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
    start         = $null
    end           = $null
    runner_image  = "$env:ImageOS $env:ImageVersion".Trim()
    engine_commit = $env:GITHUB_SHA
    seed          = $Seed
    apps          = @()
    counters      = @()
    live          = @()
}

# 1. Apps for this persona (before capture, so installers are not recorded).
$personaScript = Join-Path $PSScriptRoot "personas\$Persona.ps1"
$session.apps = @(& $personaScript -Install -LabRoot $LabRoot)

# 2. The engine records for the whole session.
$engineSeconds = [int]($Minutes * 60) + 120
$engineLog = Join-Path $Out 'engine.log'
$engine = Start-Process -FilePath $Service -ArgumentList '--console', '--seconds', $engineSeconds `
    -RedirectStandardOutput $engineLog -RedirectStandardError (Join-Path $Out 'engine.err.log') `
    -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 15
$session.start = Get-UnixNow

# 3. Health counters every 10 seconds while the engine runs.
$countersFile = Join-Path $Out 'counters.jsonl'
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

# 5. Live scenarios.
if ($LiveScenarios) {
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
            Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    $from = Get-UnixNow
    1..3 | ForEach-Object { & $curl -s -o NUL https://example.com/; Start-Sleep -Seconds 3 }
    $session.live += [ordered]@{
        scenario = "$SessionId-knownbad"; type = 'known_bad'; app_name = 'curl.exe'
        app_path = $curl; start = $from; end = Get-UnixNow; addresses = $addresses
    }
}

# 6. Let the engine finish and save, then export.
$session.end = Get-UnixNow
$engine | Wait-Process -Timeout ($engineSeconds + 120)
Stop-Job $sampler -ErrorAction SilentlyContinue; Remove-Job $sampler -Force -ErrorAction SilentlyContinue
& $Service --export (Join-Path $Out 'session.csv') | Out-Host
$rows = @(Get-Content (Join-Path $Out 'session.csv') -ErrorAction SilentlyContinue).Count - 1
$session.ok = $rows -ge 1
if (Test-Path $countersFile) {
    $session.counters = @(Get-Content $countersFile | ForEach-Object { $_ | ConvertFrom-Json })
}
$session | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $Out 'session.json') -Encoding utf8

Remove-Item -Recurse -Force $DataHome -ErrorAction SilentlyContinue
Write-Host "session $SessionId ($Persona): $rows flows, ok=$($session.ok)"
