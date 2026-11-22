<#
.SYNOPSIS
    Sums the disk writes of one or more processes, per file, from a
    Microsoft-Windows-Kernel-File trace (keywords 0x290).

.DESCRIPTION
    For every file a process writes:
    - Written: what the program wrote (cached writes);
    - To disk: paging writes for that file, by the program's own threads
      (when it flushes, e.g. SQLite's fsync) or by Windows in the System
      process (cache flushes and memory-mapped pages, e.g. SQLite's -shm).
    Each flush also makes NTFS write its own log ($LogFile, a file without a
    name in the trace that every process writes to); the paging writes to
    it from the program's threads are listed per process.

    Files are named through Create events (by file object) and NameCreate
    events and earlier writes (by file key). Cached writes to objects
    without a name (e.g. named pipes) are not disk writes and are left out.
    Only files whose name matches -FilePattern are counted.

.EXAMPLE
    .\scripts\analyse-file-writes.ps1 -Etl db-writes.etl -Processes 'light-journal=1234','light-wal=1240' -FilePattern '*.db*'
#>
param(
    [Parameter(Mandatory)] [string] $Etl,
    # label=pid pairs (a list, or one string separated by commas)
    [Parameter(Mandatory)] [string[]] $Processes,
    [string] $FilePattern = 'whereabouts.db*',
    [double] $SkipMinutes = 1
)
$ErrorActionPreference = 'Stop'
$labels = @{}
foreach ($pair in ($Processes -split ",")) {
    $label, $id = $pair -split '=', 2
    $labels[[int]$id] = $label
}
$pidFilter = ($labels.Keys | ForEach-Object { "Execution[@ProcessID=$_]" }) -join ' or '
$xpath = "*[System[(EventID=10) or (EventID=12 and ($pidFilter)) or (EventID=16 and ($pidFilter or Execution[@ProcessID=4]))]]"

$byObject = @{}
$byKey = @{}
$keyOwner = @{}
$files = @{}
$logs = @{}
$systemKeys = @{}
$start = $null; $first = $null; $last = $null
function Get-Row([hashtable] $table, [string] $id, [string] $label) {
    if (-not $table.ContainsKey($id)) {
        $table[$id] = [pscustomobject]@{ Id = $id; Label = $label; Written = [int64]0; Writes = 0; DiskByProgram = [int64]0; DiskBySystem = [int64]0 }
    }
    $table[$id]
}
Get-WinEvent -Path $Etl -Oldest -FilterXPath $xpath | ForEach-Object {
    $e = $_
    $p = $e.Properties
    switch ($e.Id) {
        10 { $byKey[[string]$p[0].Value] = [string]$p[1].Value }
        12 { $byObject[[string]$p[1].Value] = [string]$p[6].Value }
        16 {
            # ByteOffset, Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags, ...
            $object = [string]$p[2].Value
            $key = [string]$p[3].Value
            $size = [int64]$p[5].Value
            $paging = ([int64]$p[6].Value -band 2) -ne 0
            $label = $labels[[int]$e.ProcessId]
            if ($label) {
                $name = $byObject[$object]
                if (-not $name) { $name = $byKey[$key] }
                if ($name) { $byKey[$key] = $name; $keyOwner[$key] = $label }
                if ($null -eq $start) { $start = $e.TimeCreated.AddMinutes($SkipMinutes) }
            }
            else {
                $name = $byKey[$key]
                if (-not $name) { $systemKeys[$key] = $true; return }
                $label = $keyOwner[$key]
                if (-not $label) { return }
            }
            if ($null -eq $start -or $e.TimeCreated -lt $start) { return }
            if ($null -eq $first) { $first = $e.TimeCreated }
            $last = $e.TimeCreated
            if ($name) {
                if ((Split-Path $name -Leaf) -notlike $FilePattern) { return }
                $row = Get-Row $files "$label|$(Split-Path $name -Leaf)" $label
            }
            elseif ($paging) { $row = Get-Row $logs "$label|$key" $label }
            else { return }
            if (-not $paging) { $row.Written += $size; $row.Writes += 1 }
            elseif ($e.ProcessId -eq 4) { $row.DiskBySystem += $size }
            else { $row.DiskByProgram += $size }
        }
    }
}
$hours = ($last - $first).TotalHours
function Rate([int64] $bytes) { [math]::Round($bytes / 1MB / $hours, 2) }
"Window: $first to $last ({0:N2} h, first $SkipMinutes min skipped)" -f $hours
''
'Files (MB/hour):'
$files.Values | Sort-Object Id | ForEach-Object {
    [pscustomobject]@{
        Process = $_.Label
        File = ($_.Id -split '\|', 2)[1]
        Writes = $_.Writes
        Written = Rate $_.Written
        'To disk (program)' = Rate $_.DiskByProgram
        'To disk (System)' = Rate $_.DiskBySystem
    }
} | Format-Table -AutoSize | Out-String -Width 200
'Totals (MB/hour):'
$totals = foreach ($label in ($labels.Values | Sort-Object)) {
    $mine = @($files.Values | Where-Object Label -eq $label)
    $written = ($mine | Measure-Object Written -Sum).Sum
    $disk = ($mine | Measure-Object DiskByProgram -Sum).Sum + ($mine | Measure-Object DiskBySystem -Sum).Sum
    $log = (@($logs.Values | Where-Object { $_.Label -eq $label -and $systemKeys.ContainsKey(($_.Id -split '\|', 2)[1]) }) | Measure-Object DiskByProgram -Sum).Sum
    [pscustomobject]@{
        Process = $label
        'Written' = Rate $written
        'Files to disk' = Rate $disk
        'NTFS log' = Rate $log
        'To disk in all' = Rate ($disk + $log)
        'MB/day in all' = [math]::Round((Rate ($disk + $log)) * 24, 0)
    }
}
$totals | Format-Table -AutoSize | Out-String -Width 200
