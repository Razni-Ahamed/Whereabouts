# Gamer persona: Discord started logged out (update and login-screen chatter)
# while browsing with Chrome. Steam is left out (see lab/APPS.md).
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
    return @((Install-LabApp 'chrome'), (Install-LabApp 'discord'))
}
if ($Run) {
    foreach ($app in $Apps) { if ($app.id -ne 'chrome') { Start-LabApp $app } }
    Invoke-Browse -LabRoot $LabRoot -Browser 'chrome' -List 'general' -Minutes $Minutes -Seed $Seed
    Get-Process Discord -ErrorAction SilentlyContinue | Stop-Process -Force
}
