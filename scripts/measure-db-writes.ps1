<#
.SYNOPSIS
    Measures how much the history database writes to disk, rollback journal
    against write-ahead log, with the same flows at the same time.

.DESCRIPTION
    Runs four copies of the store's write_load example side by side for
    -Minutes minutes, each saving made-up flows every 2 seconds like the
    service: light and heavy traffic, each with a rollback journal and with
    a write-ahead log. Every database is first filled with 20,000 older
    flows. Windows' own file tracing (Microsoft-Windows-Kernel-File) records
    every write meanwhile; analyse it with scripts\analyse-file-writes.ps1
    (the process IDs are in run-info.txt).

    Must run as administrator (file tracing needs it). Writes only into
    -OutDir. Uses only made-up data.

.EXAMPLE
    cargo build --release --example write_load -p whereabouts-store
    # then, as administrator:
    .\scripts\measure-db-writes.ps1 -OutDir C:\Temp\db-writes -Exe target\release\examples\write_load.exe
#>
param(
    [Parameter(Mandatory)] [string] $OutDir,
    [Parameter(Mandatory)] [string] $Exe,
    [int] $Minutes = 20,
    [int] $LightPerHour = 420,
    [int] $HeavyPerHour = 16000
)
$ErrorActionPreference = 'Stop'
$session = 'WhereaboutsDbWrites'
$Exe = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$dbDir = Join-Path $OutDir 'db'
if (Test-Path $dbDir) { Remove-Item -Recurse -Force $dbDir }
New-Item -ItemType Directory $dbDir | Out-Null
$info = Join-Path $OutDir 'run-info.txt'
$etl = Join-Path $OutDir 'db-writes.etl'
function Write-Info([string] $text) { Add-Content -Path $info -Value $text -Encoding utf8; Write-Host $text }

$runs = @(
    @{ Label = 'light-journal'; Mode = 'journal'; Rate = $LightPerHour },
    @{ Label = 'light-wal'; Mode = 'wal'; Rate = $LightPerHour },
    @{ Label = 'heavy-journal'; Mode = 'journal'; Rate = $HeavyPerHour },
    @{ Label = 'heavy-wal'; Mode = 'wal'; Rate = $HeavyPerHour }
)
Set-Content -Path $info -Value "started $(Get-Date -Format o); $Minutes minutes; light $LightPerHour, heavy $HeavyPerHour flows/hour" -Encoding utf8
foreach ($run in $runs) {
    $out = & $Exe (Join-Path $dbDir "$($run.Label).db") $run.Mode $run.Rate --prefill 20000
    if ($LASTEXITCODE -ne 0) { throw "prefill failed for $($run.Label)" }
    Write-Info "$($run.Label): $out"
}

# Keywords: FILENAME 0x10 + CREATE 0x80 + WRITE 0x200. Capped at 4 GB.
logman start $session -p Microsoft-Windows-Kernel-File 0x290 0x4 -o $etl -ets -bs 1024 -nb 64 256 -max 4096 -mode Sequential | Out-Null
try {
    $processes = foreach ($run in $runs) {
        $log = Join-Path $OutDir "$($run.Label).txt"
        $p = Start-Process -FilePath $Exe -PassThru -NoNewWindow -RedirectStandardOutput $log `
            -ArgumentList @("`"$(Join-Path $dbDir "$($run.Label).db")`"", $run.Mode, $run.Rate, '--minutes', $Minutes)
        Write-Info "$($run.Label)=$($p.Id)"
        $p
    }
    $end = (Get-Date).AddMinutes($Minutes)
    while (@($processes | Where-Object { -not $_.HasExited }).Count -gt 0) {
        $left = [math]::Max(0, [int]($end - (Get-Date)).TotalMinutes)
        Write-Host "Recording... about $left minutes left. Please leave this window open."
        Start-Sleep -Seconds 30
    }
}
finally {
    logman stop $session -ets | Out-Null
    Write-Info "stopped $(Get-Date -Format o)"
    # Let a non-admin analysis read the trace.
    icacls $OutDir /grant "${env:USERDOMAIN}\${env:USERNAME}:(OI)(CI)R" /T | Out-Null
}
foreach ($run in $runs) { Write-Info "$($run.Label): $(Get-Content (Join-Path $OutDir "$($run.Label).txt"))" }
Write-Host 'Done. You can close this window.'
