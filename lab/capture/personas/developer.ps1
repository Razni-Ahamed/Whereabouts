# Developer persona: VS Code fetching an extension from its marketplace, git
# cloning public repositories, and Chrome on documentation sites.
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
    return @((Install-LabApp 'chrome'), (Install-LabApp 'vscode'))
}
if ($Run) {
    $work = Join-Path $env:TEMP "lab-dev-$Seed"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $code = $Apps | Where-Object { $_.id -eq 'vscode' -and $_.installed } | Select-Object -First 1
    if ($code) {
        $cli = Join-Path (Split-Path $code.path) 'bin\code.cmd'
        & $cli --install-extension rust-lang.rust-analyzer --force | Out-Host
    }
    foreach ($repo in 'https://github.com/rust-lang/rustlings', 'https://github.com/pallets/flask') {
        & git clone --depth 1 --quiet $repo (Join-Path $work (Split-Path $repo -Leaf))
    }
    Invoke-Browse -LabRoot $LabRoot -Browser 'chrome' -List 'developer' -Minutes ($Minutes * 0.8) -Seed $Seed
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
