# Gamer persona: Steam and Discord started logged out (launcher and update
# chatter) while browsing with Chrome.
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
    return @((Install-LabApp 'chrome'), (Install-LabApp 'steam'), (Install-LabApp 'discord'))
}
if ($Run) {
    foreach ($app in $Apps) { if ($app.id -ne 'chrome') { Start-LabApp $app } }
    Invoke-Browse -LabRoot $LabRoot -Browser 'chrome' -List 'general' -Minutes $Minutes -Seed $Seed
    Get-Process steam, steamwebhelper, Discord -ErrorAction SilentlyContinue | Stop-Process -Force
}
