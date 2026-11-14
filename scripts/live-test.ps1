<#
.SYNOPSIS
    Runs the Whereabouts live tests against real Windows ETW events.

.DESCRIPTION
    1. Builds everything as the current user.
    2. Runs the live tests with administrator rights (one UAC prompt):
       - the ignored integration tests in crates/win-capture/tests/live_capture.rs
       - a smoke test of `whereabouts-service --console` while curl.exe downloads a page,
         including `--status` over the local pipe as administrator and as a normal user
    3. With -Service, also installs Whereabouts as a Windows service, checks it, and
       removes it again (the saved-data folder too, unless it existed before).
    4. Prints PASS or FAIL and exits with 0 on success, 1 on failure.

    The tests make a few HTTPS requests to example.com. Logs, which contain
    this computer's connection metadata, are written to a temporary folder
    and are never committed.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\live-test.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\live-test.ps1 -Service
#>
[CmdletBinding()]
param(
    # Also test the Windows service: install, check, uninstall.
    [switch]$Service,
    # Internal: set when the script re-runs itself with administrator rights.
    [switch]$Elevated,
    # Internal: folder where the elevated run writes its logs.
    [string]$WorkDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $Cargo)) { $Cargo = 'cargo' }
$ServiceExe = Join-Path $RepoRoot 'target\debug\whereabouts-service.exe'
# SQLCipher's OpenSSL build needs a native Windows Perl (Strawberry Perl).
$StrawberryPerl = 'C:\Strawberry\perl\bin\perl.exe'
if (Test-Path $StrawberryPerl) { $env:OPENSSL_SRC_PERL = $StrawberryPerl }
$TestUrl = 'https://example.com'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param([string]$Text)
    Write-Host $Text
    Add-Content -Path (Join-Path $WorkDir 'live-test.log') -Value $Text -Encoding UTF8
}

# Starts a program with its output redirected to files in $WorkDir.
function Start-Logged {
    param([string]$FilePath, [string[]]$Arguments, [string]$Name)
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
        -WorkingDirectory $RepoRoot -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $WorkDir "$Name.out.txt") `
        -RedirectStandardError (Join-Path $WorkDir "$Name.err.txt")
    # Reading Handle now makes ExitCode available after the process exits.
    $null = $process.Handle
    return $process
}

# Runs a program to the end and returns its output.
function Invoke-Program {
    param([string]$FilePath, [string]$Name, [string[]]$Arguments)
    $process = Start-Logged -FilePath $FilePath -Name $Name -Arguments $Arguments
    if (-not $process.WaitForExit(120000)) { $process.Kill() }
    return Get-LoggedOutput -Name $Name
}

# Runs a program as a normal user: the same account without administrator
# rights ("basic user", runas /trustlevel:0x20000). Returns its output.
function Invoke-AsNormalUser {
    param([string]$FilePath, [string]$Name, [string]$Arguments)
    $log = Join-Path $WorkDir "$Name.log"
    $cmd = Join-Path $WorkDir "$Name.cmd"
    Set-Content -Path $cmd -Encoding ascii -Value "@`"$FilePath`" $Arguments > `"$log`" 2>&1"
    & runas.exe /trustlevel:0x20000 $cmd | Out-Null
    $deadline = (Get-Date).AddSeconds(15)
    while (-not (Test-Path $log) -or (Get-Item $log).Length -eq 0) {
        if ((Get-Date) -gt $deadline) { break }
        Start-Sleep -Milliseconds 200
    }
    Start-Sleep -Milliseconds 500
    if (Test-Path $log) { return Get-Content -Raw $log } else { return '' }
}

function Get-LoggedOutput {
    param([string]$Name)
    $text = ''
    foreach ($suffix in 'out', 'err') {
        $path = Join-Path $WorkDir "$Name.$suffix.txt"
        if (Test-Path $path) {
            $content = Get-Content -Path $path -Raw -Encoding UTF8
            if ($content) { $text += $content }
        }
    }
    return $text
}

function Invoke-IntegrationTests {
    Write-Log '--- 1/3  ETW integration tests ---'
    $process = Start-Logged -FilePath $Cargo -Name 'integration' -Arguments @(
        'test', '-p', 'whereabouts-win-capture', '--test', 'live_capture',
        '--', '--ignored', '--test-threads=1')
    if (-not $process.WaitForExit(300000)) {
        $process.Kill()
        Write-Log 'FAIL: integration tests timed out after 5 minutes'
        return $false
    }
    $output = Get-LoggedOutput -Name 'integration'
    $output -split "`r?`n" | Where-Object { $_ -match '^test |test result|panicked|assert' } |
        ForEach-Object { Write-Log "    $_" }
    if ($process.ExitCode -ne 0 -or $output -notmatch 'test result: ok\. 4 passed') {
        Write-Log "FAIL: integration tests (exit code $($process.ExitCode))"
        return $false
    }
    Write-Log 'ok: integration tests'
    return $true
}

function Invoke-Service {
    param([string]$Name, [string[]]$Arguments)
    return Invoke-Program -FilePath $ServiceExe -Name $Name -Arguments $Arguments
}

function Invoke-ConsoleSmokeTest {
    Write-Log '--- 2/3  Console smoke test ---'
    # Save into a temporary folder, never the real %ProgramData%\Whereabouts.
    $env:WHEREABOUTS_HOME = Join-Path $WorkDir 'home'
    $console = Start-Logged -FilePath $ServiceExe -Name 'console' -Arguments @(
        '--console', '--seconds', '16')
    Start-Sleep -Seconds 4
    # Empty the DNS cache so curl's lookup is confirmed by the DNS service.
    & ipconfig /flushdns | Out-Null
    $curl = Start-Process -FilePath 'curl.exe' -NoNewWindow -Wait -PassThru -ArgumentList @(
        '--silent', '--output', 'NUL', '--max-time', '15', $TestUrl)
    Write-Log "    curl.exe (pid $($curl.Id)) exited with $($curl.ExitCode)"
    # A renamed copy must still be recognised by its signature.
    $renamedPath = Join-Path $WorkDir 'renamed-tool.exe'
    Copy-Item -Path (Join-Path $env:SystemRoot 'System32\curl.exe') -Destination $renamedPath
    $renamed = Start-Process -FilePath $renamedPath -NoNewWindow -Wait -PassThru -ArgumentList @(
        '--silent', '--output', 'NUL', '--max-time', '15', $TestUrl)
    Write-Log "    renamed-tool.exe (pid $($renamed.Id)) exited with $($renamed.ExitCode)"

    # While the console runs, ask it for its status over the local pipe:
    # as administrator, and as a normal user (as the desktop app will).
    Start-Sleep -Seconds 3
    $statusOk = $true
    $status = Invoke-Service -Name 'status' -Arguments @('--status')
    if ($status -notmatch 'is running' -or $status -notmatch 'Top flows now') {
        Write-Log 'FAIL: --status (as administrator) did not get an answer from the console'
        Write-Log $status
        $statusOk = $false
    } else {
        Write-Log '    --status as administrator: answered'
    }
    $basic = Invoke-AsNormalUser -FilePath $ServiceExe -Name 'status-basic' -Arguments '--status'
    if ($basic -notmatch 'is running') {
        Write-Log 'FAIL: --status as a normal user did not get an answer from the console'
        Write-Log $basic
        $statusOk = $false
    } else {
        Write-Log '    --status as a normal user: answered'
    }

    if (-not $console.WaitForExit(60000)) {
        $console.Kill()
        Write-Log 'FAIL: console did not exit within 60 seconds'
        return $false
    }
    $output = Get-LoggedOutput -Name 'console'
    $summaries = @($output -split "`r?`n" | Where-Object { $_ -like '*active flows*' })
    $passed = $true
    if ($console.ExitCode -ne 0) {
        Write-Log "FAIL: console exited with $($console.ExitCode)"
        $passed = $false
    }
    if ($summaries.Count -eq 0) {
        Write-Log 'FAIL: console printed no summary line'
        $passed = $false
    } else {
        $last = $summaries[-1]
        Write-Log "    $last"
        if ($last -notmatch ' 0 unreadable') {
            Write-Log 'FAIL: some events could not be decoded'
            $passed = $false
        }
    }
    $curlRows = @($output -split "`r?`n" | Where-Object { $_ -match "^\s*$($curl.Id)\s+curl\.exe\s" })
    if ($curlRows.Count -eq 0) {
        Write-Log "FAIL: curl.exe (pid $($curl.Id)) is not in the console table"
        $passed = $false
    } else {
        Write-Log "    $($curlRows[-1].Trim())"
        # A verified label has no "?" or "*" marker after the name.
        if ($curlRows[-1] -notmatch '\sexample\.com\s') {
            Write-Log 'FAIL: curl.exe row is not labelled with a verified example.com'
            $passed = $false
        }
        # curl.exe is listed in more than one Microsoft-signed catalog
        # ("Microsoft Windows", "Microsoft 3rd Party Application Component").
        if ($curlRows[-1] -notmatch 'curl\.exe\s+Microsoft ') {
            Write-Log 'FAIL: curl.exe row does not show a Microsoft publisher'
            $passed = $false
        }
    }
    $renamedRows = @($output -split "`r?`n" | Where-Object { $_ -match "^\s*$($renamed.Id)\s+renamed-tool\.exe\s" })
    if ($renamedRows.Count -eq 0) {
        Write-Log "FAIL: renamed-tool.exe (pid $($renamed.Id)) is not in the console table"
        $passed = $false
    } else {
        Write-Log "    $($renamedRows[-1].Trim())"
        if ($renamedRows[-1] -notmatch 'renamed-tool\.exe\s+Microsoft ') {
            Write-Log 'FAIL: the renamed copy of curl.exe is not recognised as Microsoft-signed'
            $passed = $false
        }
    }
    if (-not $statusOk) { $passed = $false }
    if ($passed) { Write-Log 'ok: console smoke test' }
    return $passed
}

function Invoke-StorageTest {
    Write-Log '--- 3/3  Encrypted storage ---'
    $dataHome = $env:WHEREABOUTS_HOME
    $passed = $true

    $history = Invoke-Service -Name 'history' -Arguments @('--history')
    $saved = @($history -split "`r?`n" | Where-Object { $_ -like 'Saved flows:*' })
    if ($saved.Count -gt 0) { Write-Log "    $($saved[0])" }
    if ($history -notmatch '(?m)^curl\.exe\s') {
        Write-Log 'FAIL: curl.exe is not in the saved history'
        $passed = $false
    }

    $database = Join-Path $dataHome 'whereabouts.db'
    if (-not (Test-Path $database)) {
        Write-Log 'FAIL: no database file'
        return $false
    }
    $raw = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($database))
    foreach ($needle in @('curl.exe', 'example.com', 'SQLite format 3')) {
        if ($raw.Contains($needle)) {
            Write-Log "FAIL: '$needle' is readable in the database file"
            $passed = $false
        }
    }
    if ($passed) { Write-Log '    database file: no readable app names, domains or SQLite header' }

    $access = @((Get-Acl $dataHome).Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    Write-Log "    folder access: $($access -join ', ')"
    if (@($access | Where-Object { $_ -notmatch '\\SYSTEM$|\\Administrators$' }).Count -gt 0) {
        Write-Log 'FAIL: the data folder is open to more than SYSTEM and Administrators'
        $passed = $false
    }

    $csv = Join-Path $WorkDir 'export.csv'
    $null = Invoke-Service -Name 'export' -Arguments @('--export', $csv)
    if (-not (Test-Path $csv) -or -not (Select-String -Path $csv -Pattern 'curl\.exe' -Quiet)) {
        Write-Log 'FAIL: export does not contain curl.exe'
        $passed = $false
    } else {
        Write-Log "    export: $((Get-Content $csv).Count - 1) flows"
    }

    # A data folder created beforehand by a normal (non-admin) account, as an
    # attacker could do in %ProgramData%, must be refused.
    $planted = Join-Path $WorkDir 'planted-home'
    if (Test-Path $planted) {
        $real = $env:WHEREABOUTS_HOME
        $env:WHEREABOUTS_HOME = $planted
        $refused = Invoke-Service -Name 'planted' -Arguments @('--history')
        $env:WHEREABOUTS_HOME = $real
        if ($refused -notmatch 'owned by an account') {
            Write-Log 'FAIL: a data folder created by a normal account was not refused'
            $passed = $false
        } else {
            Write-Log '    planted folder (created by a normal account): refused'
        }
    }

    $null = Invoke-Service -Name 'delete' -Arguments @('--delete-all', '--yes')
    $after = Invoke-Service -Name 'history-after' -Arguments @('--history')
    if ($after -notmatch 'Saved flows: 0') {
        Write-Log 'FAIL: flows remain after --delete-all --yes'
        $passed = $false
    } else {
        Write-Log '    delete-all: 0 flows left'
    }

    if ($passed) { Write-Log 'ok: encrypted storage' }
    return $passed
}

function Invoke-ServiceTest {
    Write-Log '--- extra  Windows service (installed, checked, then removed) ---'
    # The service uses the real data folder, so these commands must too.
    Remove-Item Env:WHEREABOUTS_HOME -ErrorAction SilentlyContinue
    $installDir = Join-Path $env:ProgramFiles 'Whereabouts'
    $installed = Join-Path $installDir 'whereabouts-service.exe'
    $dataHome = Join-Path $env:ProgramData 'Whereabouts'
    $hadData = Test-Path $dataHome
    if (Get-Service -Name 'Whereabouts' -ErrorAction SilentlyContinue) {
        Write-Log 'FAIL: the Whereabouts service is already installed; uninstall it first'
        return $false
    }
    $passed = $true
    function Fail([string]$Message, [string]$Details = '') {
        Write-Log "FAIL: $Message"
        if ($Details) { Write-Log $Details }
        Set-Variable -Name passed -Value $false -Scope 1
    }

    $out = Invoke-Service -Name 'install' -Arguments @('--install')
    $svc = Get-CimInstance Win32_Service -Filter "Name='Whereabouts'"
    if (-not $svc -or $svc.State -ne 'Running') {
        Fail 'the service is not running after --install' $out
    } else {
        Write-Log "    installed: $($svc.State), start $($svc.StartMode), as $($svc.StartName)"
        if ($svc.StartMode -ne 'Auto') { Fail 'the service does not start automatically' }
        if ($svc.StartName -ne 'LocalSystem') { Fail 'the service does not run as LocalSystem' }
        if (-not $svc.PathName.StartsWith("`"$installed`"")) { Fail "unexpected service path $($svc.PathName)" }
    }

    # Normal users must not be able to change the program SYSTEM runs.
    # WriteData, AppendData, Delete, ChangePermissions, TakeOwnership,
    # GenericWrite, GenericAll.
    $writeRights = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    foreach ($path in @($installDir, $installed)) {
        $open = @((Get-Acl $path).Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            ($_.IdentityReference.Value -in @('BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'Everyone', 'NT AUTHORITY\INTERACTIVE', $me)) -and
            (([int64]$_.FileSystemRights -band $writeRights) -ne 0)
        })
        if ($open.Count -gt 0) { Fail "normal users can change $path" ($open | Out-String) }
    }
    Write-Log '    program folder: not changeable by normal users'

    & ipconfig /flushdns | Out-Null
    $curl = Start-Process -FilePath 'curl.exe' -NoNewWindow -Wait -PassThru -ArgumentList @(
        '--silent', '--output', 'NUL', '--max-time', '15', $TestUrl)
    Write-Log "    curl.exe (pid $($curl.Id)) exited with $($curl.ExitCode)"
    Start-Sleep -Seconds 4

    $status = Invoke-Program -FilePath $installed -Name 'svc-status' -Arguments @('--status')
    if ($status -notmatch 'is running' -or $status -notmatch 'saving history: yes') {
        Fail '--status (installed copy, administrator) did not get a full answer' $status
    } else { Write-Log '    --status from the installed copy, as administrator: answered' }
    $basic = Invoke-AsNormalUser -FilePath $installed -Name 'svc-status-basic' -Arguments '--status'
    if ($basic -notmatch 'is running') {
        Fail '--status (installed copy, normal user) did not get an answer' $basic
    } else { Write-Log '    --status from the installed copy, as a normal user: answered' }
    $other = Invoke-Service -Name 'svc-status-other' -Arguments @('--status')
    # The other copy trusts the service (the Service Control Manager vouches
    # for it), but the service refuses a program that is not its own file.
    if ($other -notmatch 'only answers its own program') {
        Fail 'the service did not refuse another copy of the program' $other
    } else { Write-Log '    --status from another copy of the program: refused by the service' }
    $console = Invoke-Service -Name 'svc-console' -Arguments @('--console', '--seconds', '1')
    if ($console -notmatch 'service is running') {
        Fail '--console started while the service was running' $console
    } else { Write-Log '    --console while the service runs: refused' }

    $out = Invoke-Service -Name 'uninstall' -Arguments @('--uninstall')
    if (Get-Service -Name 'Whereabouts' -ErrorAction SilentlyContinue) { Fail 'the service is still installed' $out }
    if (Test-Path $installDir) { Fail "$installDir is still there" $out }
    if (-not (Get-Service -Name 'Whereabouts' -ErrorAction SilentlyContinue) -and -not (Test-Path $installDir)) { Write-Log '    --uninstall: service and program folder removed' }

    # Saved by the service (SYSTEM), read by an administrator: the key is
    # shared through machine-scope DPAPI.
    $csv = Join-Path $WorkDir 'service-export.csv'
    $null = Invoke-Service -Name 'svc-export' -Arguments @('--export', $csv)
    $curlSaved = (Test-Path $csv) -and (Select-String -Path $csv -Pattern 'curl\.exe' -Quiet)
    if (-not $curlSaved) { Fail 'the flows the service saved could not be read, or curl.exe is missing' }
    else { Write-Log '    history saved by the service: readable by an administrator, includes curl.exe' }
    Remove-Item $csv -ErrorAction SilentlyContinue

    $logFile = Join-Path $dataHome 'service.log'
    $logText = if (Test-Path $logFile) { Get-Content -Raw $logFile } else { '' }
    if ($logText -notmatch 'service started' -or $logText -notmatch 'service stopped') {
        Fail 'the service log does not show a clean start and stop' $logText
    } elseif ($logText -match 'error:') {
        Fail 'the service log has errors' $logText
    } else { Write-Log '    service log: clean start and stop, no errors' }

    if (-not $hadData) {
        $out = Invoke-Service -Name 'delete-data' -Arguments @('--uninstall', '--delete-data')
        if (Test-Path $dataHome) { Fail "$dataHome was not deleted" $out }
        else { Write-Log '    --uninstall --delete-data: data folder deleted' }
    } else {
        Write-Log "    kept $dataHome (it existed before this test)"
    }
    if ($passed) { Write-Log 'ok: Windows service' }
    return $passed
}

function Invoke-LiveTests {
    $integration = Invoke-IntegrationTests
    $console = Invoke-ConsoleSmokeTest
    $storage = Invoke-StorageTest
    # (PowerShell names ignore case: a variable called $service would
    # overwrite the -Service switch.)
    $serviceOk = $true
    if ($Service) { $serviceOk = Invoke-ServiceTest }
    return ($integration -and $console -and $storage -and $serviceOk)
}

# --- Elevated part -----------------------------------------------------------
if ($Elevated) {
    try {
        if (Invoke-LiveTests) { exit 0 } else { exit 1 }
    } catch {
        Write-Log "FAIL: $_"
        exit 1
    }
}

# --- Normal part -------------------------------------------------------------
$WorkDir = Join-Path ([IO.Path]::GetTempPath()) ("whereabouts-live-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $WorkDir | Out-Null

Write-Host 'Building (as the current user)...'
& $Cargo build -p whereabouts-service
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: build failed'; exit 1 }
& $Cargo test -p whereabouts-win-capture --test live_capture --no-run
if ($LASTEXITCODE -ne 0) { Write-Host 'FAIL: test build failed'; exit 1 }

if (Test-IsAdministrator) {
    $passed = Invoke-LiveTests
} else {
    # Created as the normal user, so it is owned by that account.
    New-Item -ItemType Directory -Path (Join-Path $WorkDir 'planted-home') | Out-Null
    Write-Host 'Running live tests as administrator. Please approve the UAC prompt...'
    $elevatedArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"", '-Elevated', '-WorkDir', "`"$WorkDir`"")
    if ($Service) { $elevatedArgs += '-Service' }
    try {
        $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru `
            -WindowStyle Hidden -ArgumentList $elevatedArgs
    } catch {
        Write-Host 'FAIL: administrator rights were not granted (UAC prompt declined?)'
        exit 1
    }
    $log = Join-Path $WorkDir 'live-test.log'
    if (Test-Path $log) { Get-Content -Path $log -Encoding UTF8 | Write-Host }
    $passed = ($child.ExitCode -eq 0)
}

Write-Host ''
Write-Host "Logs: $WorkDir"
if ($passed) {
    Write-Host 'PASS: all live tests passed' -ForegroundColor Green
    exit 0
} else {
    Write-Host 'FAIL: see the messages above' -ForegroundColor Red
    exit 1
}
