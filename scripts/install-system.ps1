<#
.SYNOPSIS
Install ambitd as a system service on Windows, the way a monitoring agent like Sysmon
runs: as SYSTEM, from boot, restarted whenever it exits.

.DESCRIPTION
The Windows counterpart of install-system.sh.

ambitd is a console program, not a Windows service: turning it into one would add a
dependency to a daemon that ships to every endpoint with none. So it runs as a
scheduled task instead: at startup, as SYSTEM, with no time limit, restarted a minute
after it exits. Task Scheduler restarts a task only when it ends in failure, which is
what a crash or a kill looks like; ambitd never exits cleanly on its own.

What install does, in this order:
  1. creates C:\ProgramData\ambit private to SYSTEM and Administrators (ambitd refuses
     a data directory other accounts can read), and copies the binary to
     C:\Program Files\ambit\ambitd.exe;
  2. registers and starts the task, and waits for the health endpoint;
  3. only then installs the observation-only managed-settings bundle to
     C:\Program Files\ClaudeCode\managed-settings.json, so Claude Code is never pointed
     at a daemon that is not there.

It refuses to replace managed settings that already exist and differ from the bundle:
an organization's own policy may be in that file. Merge the bundle's "env" and "hooks"
blocks into it by hand instead.

Uninstall reverses the order: managed settings first, then the task. The spool and the
fingerprint key stay unless -Purge is given.

ambitd's output goes to C:\ProgramData\ambit\ambitd.log, which is not rotated.

NOT VERIFIED ON A LIVE WINDOWS MACHINE: the task's restart-on-failure behavior and the
cmd.exe log redirection. Kill ambitd.exe on a test machine and watch it return.

.PARAMETER Binary
The ambitd.exe built for this machine's CPU (make cross writes
bin\ambitd-windows-amd64.exe and bin\ambitd-windows-arm64.exe).

.PARAMETER Status
Show whether the task is running and the health endpoint answers.

.PARAMETER Uninstall
Remove managed settings (if they are the M0 bundle), the task and the binary.

.PARAMETER Purge
With -Uninstall, also remove C:\ProgramData\ambit.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\scripts\install-system.ps1 -Binary .\bin\ambitd-windows-amd64.exe

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\scripts\install-system.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Binary = '',
    [switch]$Status,
    [switch]$Uninstall,
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$Root = Split-Path -Parent $PSScriptRoot

# A 32-bit PowerShell on 64-bit Windows sees "Program Files (x86)" as ProgramFiles.
# Claude Code reads managed settings from the 64-bit Program Files only.
$ProgramFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }

$BinDir   = Join-Path $ProgramFiles 'ambit'
$BinPath  = Join-Path $BinDir 'ambitd.exe'
$DataDir  = Join-Path $env:ProgramData 'ambit'
$Config   = Join-Path $DataDir 'config.json'
$LogPath  = Join-Path $DataDir 'ambitd.log'
$Managed  = Join-Path $ProgramFiles 'ClaudeCode\managed-settings.json'
$Bundle   = Join-Path $Root 'deploy\claude-code\managed-settings.m0.json'
$TaskName = 'ambitd'
$TaskPath = '\ambit\'
$Icacls   = Join-Path $env:SystemRoot 'System32\icacls.exe'
$Cmd      = Join-Path $env:SystemRoot 'System32\cmd.exe'

# SIDs rather than names, which are localized on non-English Windows.
$SidSystem = 'S-1-5-18'
$SidAdmins = 'S-1-5-32-544'

function Say([string]$msg) { Write-Host "install-system: $msg" }
function Die([string]$msg) { throw "install-system: $msg" }

function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Die 'run from an Administrator PowerShell: the task, the binary and managed settings live in system paths'
    }
}

# The binary whose effective configuration says where ambitd listens: the one being
# installed during an install, the installed one otherwise.
$script:ProbeBin = $BinPath

function Get-HookUrl {
    $addr = ''
    if (Test-Path -LiteralPath $script:ProbeBin) {
        try {
            $json = (& $script:ProbeBin -config $Config -print-config 2>$null | Out-String)
            $addr = ($json | ConvertFrom-Json).hook_addr
        } catch { $addr = '' }
    }
    if (-not $addr) { $addr = '127.0.0.1:7777' }
    return "http://$addr"
}

function Test-Healthy {
    try {
        $null = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri ((Get-HookUrl) + '/healthz')
        return $true
    } catch {
        return $false
    }
}

function Get-TaskState {
    $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($null -eq $t) { return 'not registered' }
    return [string]$t.State
}

function Test-Running { return (Get-TaskState) -eq 'Running' }

# Wait for the task itself to be running AND the endpoint to answer. The endpoint alone
# is not proof: another process holding the port answers just as well.
function Wait-Healthy {
    for ($i = 0; $i -lt 20; $i++) {
        if ((Test-Running) -and (Test-Healthy)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Stop-Ambitd {
    $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($null -ne $t) {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    }
    # Stopping the task ends cmd.exe; make sure the ambitd.exe it started is gone too,
    # or the binary cannot be replaced and the port stays held.
    Get-Process -Name ambitd -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $BinPath } |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# The data directory must exist before the task starts, because cmd.exe opens the log
# inside it. ambitd refuses one that other accounts can read or that an account other
# than itself, SYSTEM or Administrators owns, so set both explicitly.
function New-DataDir {
    if (Test-Path -LiteralPath $DataDir) { return }
    New-Item -ItemType Directory -Path $DataDir | Out-Null
    & $Icacls $DataDir /setowner "*$SidSystem" | Out-Null
    $c1 = $LASTEXITCODE
    & $Icacls $DataDir /inheritance:r /grant:r "*${SidSystem}:(OI)(CI)F" /grant:r "*${SidAdmins}:(OI)(CI)F" | Out-Null
    $c2 = $LASTEXITCODE
    if ($c1 -ne 0 -or $c2 -ne 0) {
        Remove-Item -LiteralPath $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        Die "could not restrict $DataDir with icacls; removed it so a re-run starts clean"
    }
}

function Register-AmbitdTask {
    # cmd /c ""exe" args >> "log" 2>&1": the outer quotes are stripped by cmd, the inner
    # ones keep paths with spaces intact.
    $arg = '/d /c ""' + $BinPath + '" -config "' + $Config + '" >> "' + $LogPath + '" 2>&1"'
    $action    = New-ScheduledTaskAction -Execute $Cmd -Argument $arg
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # ExecutionTimeLimit zero means no limit; the default would kill ambitd after 72 hours.
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action `
        -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
}

function Test-SameFile([string]$a, [string]$b) {
    return (Get-FileHash -LiteralPath $a).Hash -eq (Get-FileHash -LiteralPath $b).Hash
}

function Install-ManagedSettings {
    if (Test-Path -LiteralPath $Managed) {
        if (Test-SameFile $Bundle $Managed) {
            Say "managed settings already match the M0 bundle: $Managed"
            return
        }
        Die ("managed settings already exist at $Managed and differ from the M0 bundle. " +
             "They may carry your organization's own policy, so they were not replaced. " +
             "ambitd is installed and running; merge the 'env' and 'hooks' blocks of $Bundle " +
             "into that file by hand, then confirm a Claude Code session produces events.")
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Managed) -Force | Out-Null
    Copy-Item -LiteralPath $Bundle -Destination $Managed
    Say "installed managed settings: $Managed"
}

function Remove-ManagedSettings {
    if (-not (Test-Path -LiteralPath $Managed)) { return }
    if (Test-SameFile $Bundle $Managed) {
        Remove-Item -LiteralPath $Managed -Force
        Say "removed managed settings: $Managed"
    } else {
        Say "left $Managed in place: it differs from the M0 bundle, so it is not only ours. Remove the ambit 'hooks' and OTEL 'env' entries from it by hand."
    }
}

function Invoke-Install {
    Assert-Admin
    if (-not $Binary) { Die '-Binary is required: the ambitd.exe built for this CPU (make cross writes bin\ambitd-windows-<arch>.exe)' }
    if (-not (Test-Path -LiteralPath $Binary)) { Die "no such file: $Binary" }
    if (-not (Test-Path -LiteralPath $Bundle)) { Die "missing $Bundle; run this from a checkout of the repository" }
    $src = (Resolve-Path -LiteralPath $Binary).Path

    # Running -version proves the binary is for this CPU before anything changes.
    $ver = ''
    try { $ver = (& $src -version 2>$null | Out-String).Trim() } catch { $ver = '' }
    if (-not $ver) { Die "$src does not run here: wrong CPU architecture?" }
    $script:ProbeBin = $src

    # A user-scope ambitd (dev-local.ps1) holds the same port, and the task's ambitd would
    # fail to bind. Only fail if what answers is not already this task.
    if ((Test-Healthy) -and -not (Test-Running)) {
        Die ("something already answers on $(Get-HookUrl): probably a user-scope ambitd. " +
             'Remove it first with .\scripts\dev-local.ps1 -Uninstall')
    }

    New-DataDir
    Stop-Ambitd
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item -LiteralPath $src -Destination $BinPath -Force
    Say "installed $BinPath ($ver)"

    Register-AmbitdTask
    if (-not (Wait-Healthy)) {
        Die "the task did not come up on $(Get-HookUrl); see $LogPath and Get-ScheduledTaskInfo -TaskPath '$TaskPath' -TaskName $TaskName"
    }
    Say "task running, health endpoint answers on $(Get-HookUrl)"

    Install-ManagedSettings
    Say "done. Data: $DataDir. Start a Claude Code session and check that events.jsonl there gains a session_start line."
}

function Invoke-Uninstall {
    Assert-Admin
    Remove-ManagedSettings
    Stop-Ambitd
    if ((Get-TaskState) -ne 'not registered') {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    }
    if (Test-Path -LiteralPath $BinDir) { Remove-Item -LiteralPath $BinDir -Recurse -Force }
    Say 'task and binary removed'
    if ($Purge) {
        if (Test-Path -LiteralPath $DataDir) { Remove-Item -LiteralPath $DataDir -Recurse -Force }
        Say "removed $DataDir"
    } elseif (Test-Path -LiteralPath $DataDir) {
        Say "kept $DataDir (spool, events, fingerprint key, log); -Purge removes it"
    }
}

function Show-Status {
    Write-Host ("task:             " + (Get-TaskState))
    if (Test-Healthy) { Write-Host ("health endpoint:  answers on " + (Get-HookUrl)) }
    else { Write-Host ("health endpoint:  no answer on " + (Get-HookUrl)) }
    if (Test-Path -LiteralPath $BinPath) { Write-Host "binary:           $BinPath" }
    else { Write-Host 'binary:           not installed' }
    if (Test-Path -LiteralPath $Managed) {
        if (Test-SameFile $Bundle $Managed) { Write-Host "managed settings: the M0 bundle ($Managed)" }
        else { Write-Host "managed settings: present, not the M0 bundle ($Managed)" }
    } else {
        Write-Host 'managed settings: absent'
    }
    Write-Host "data:             $DataDir"
}

if ($Purge -and -not $Uninstall) { Die '-Purge only goes with -Uninstall' }
if ($Status) { Show-Status }
elseif ($Uninstall) { Invoke-Uninstall }
else { Invoke-Install }
