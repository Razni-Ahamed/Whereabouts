# Office persona: Microsoft Edge (preinstalled) and Chrome on news, shopping
# and reference sites, with Windows Update checking in the background.
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
    return @(Install-LabApp 'chrome')
}
if ($Run) {
    Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList 'StartScan' -ErrorAction SilentlyContinue
    Invoke-Browse -LabRoot $LabRoot -Browser 'msedge' -List 'general' -Minutes ($Minutes * 0.6) -Seed $Seed
    Invoke-Browse -LabRoot $LabRoot -Browser 'chrome' -List 'general' -Minutes ($Minutes * 0.4) -Seed ($Seed + 1)
}
