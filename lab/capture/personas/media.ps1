# Media persona: Spotify started logged out (its own background chatter)
# while browsing with Firefox (Playwright's build).
# Uses Install-LabApp / Start-LabApp from run-session.ps1. With -Install it
# returns the app records; with -Run it uses the apps for -Minutes.
param(
    [switch]$Install,
    [switch]$Run,
    [Parameter(Mandatory)][string]$LabRoot,
    [double]$Minutes,
    [int]$Seed,
    [object[]]$Apps
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if ($Install) {
    & uv run --project $LabRoot playwright install firefox | Out-Host
    return @(Install-LabApp 'spotify')
}
if ($Run) {
    foreach ($app in $Apps) { Start-LabApp $app }
    Invoke-Browse -LabRoot $LabRoot -Browser 'firefox' -List 'general' -Minutes $Minutes -Seed $Seed
    Get-Process Spotify -ErrorAction SilentlyContinue | Stop-Process -Force
}
