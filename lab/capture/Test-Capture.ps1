<#
.SYNOPSIS
    Checks one captured session folder (run in the lab workflow after
    run-session.ps1). Exits 1 with the reasons when something is wrong.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Out,
    [switch]$LiveScenarios
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$problems = @()
$jsonPath = Join-Path $Out 'session.json'
$csvPath = Join-Path $Out 'session.csv'
$expectedHeader = 'app_name,app_path,app_sha256,signature,publisher,signature_confirmed,protocol,remote_ip,remote_port,domain,domain_source,owner,country,first_seen_unix_ms,last_seen_unix_ms,bytes_sent,bytes_received,connections'

if (-not (Test-Path $jsonPath)) { $problems += 'session.json is missing' }
else {
    $session = Get-Content $jsonPath -Raw | ConvertFrom-Json
    if ($session.PSObject.Properties['error'] -and $session.error) { $problems += "the session failed: $($session.error)" }
    if (-not $session.ok) { $problems += 'the session captured no flows (ok is false)' }
    if (@($session.counters).Count -lt 1) { $problems += 'no health-counter samples (--status --json)' }
    if ($LiveScenarios) {
        foreach ($type in 'renamed_binary', 'known_bad') {
            if (-not (@($session.live) | Where-Object { $_.type -eq $type })) { $problems += "live label $type is missing" }
        }
        $bad = @($session.live) | Where-Object { $_.type -eq 'known_bad' }
        if ($bad -and @($bad.addresses).Count -lt 1) { $problems += 'known_bad has no example.com addresses' }
    }
    foreach ($app in @($session.apps)) {
        if (-not $app.installed) { Write-Warning "app $($app.id) is not installed (via $($app.via))" }
    }
}
if (-not (Test-Path $csvPath)) { $problems += 'session.csv is missing' }
elseif ((Get-Content $csvPath -TotalCount 1) -ne $expectedHeader) { $problems += 'session.csv has an unexpected header' }

# When each connection was opened (--record-connections): one JSON object per line.
$connectionsPath = Join-Path $Out 'connections.jsonl'
if (-not (Test-Path $connectionsPath)) { $problems += 'connections.jsonl is missing (--record-connections)' }
else {
    $first = Get-Content $connectionsPath -TotalCount 1
    if (-not $first) { Write-Warning 'connections.jsonl is empty: no connection of a known program was recorded' }
    else {
        try {
            $line = $first | ConvertFrom-Json
            foreach ($name in 'app_path', 'app_name', 'destination', 'remote_ip', 'remote_port', 'time_ms') {
                if (-not $line.PSObject.Properties[$name]) { $problems += "connections.jsonl lines lack $name" }
            }
        } catch {
            $problems += "connections.jsonl is not JSON lines: $_"
        }
    }
}

if ($problems) {
    $problems | ForEach-Object { Write-Host "FAIL: $_" }
    exit 1
}
Write-Host "session in $Out looks right"
