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

function Wait-Healthy {
    for ($i = 0; $i -lt 20; $i++) {
        if ((Test-Running) -and (Test-Healthy)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-AmbitdProcess {
    return @(Get-Process -Name ambitd -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $BinPath })
}

function Stop-Ambitd {
    $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($null -ne $t) {
        Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath | Out-Null
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    }
    Get-AmbitdProcess | Stop-Process -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 40; $i++) {
        if ((Get-AmbitdProcess).Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    }
    Die 'ambitd is still running 10 seconds after it was stopped, so its binary cannot be replaced'
}

function Get-KeepAliveProblem([string]$TaskXml) {
    $doc = New-Object System.Xml.XmlDocument
    try { $doc.LoadXml($TaskXml) } catch { return 'the task definition is not readable XML' }
    if ($doc.SelectNodes('//*[local-name()=''BootTrigger'']').Count -lt 1) {
        return 'no boot trigger'
    }
    $intervals = @($doc.SelectNodes('//*[local-name()=''TimeTrigger'']/*[local-name()=''Repetition'']/*[local-name()=''Interval'']'))
    if (@($intervals | Where-Object { $_.InnerText -eq 'PT1M' }).Count -lt 1) {
        return 'no one-minute repeating trigger, so a killed ambitd is not brought back'
    }
    $policy = $doc.SelectSingleNode('//*[local-name()=''Settings'']/*[local-name()=''MultipleInstancesPolicy'']')
    if ($null -eq $policy -or $policy.InnerText -ne 'IgnoreNew') {
        return 'MultipleInstances is not IgnoreNew, so an overlapping start could run two daemons'
    }
    $enabled = $doc.SelectSingleNode('//*[local-name()=''Settings'']/*[local-name()=''Enabled'']')
    if ($null -ne $enabled -and $enabled.InnerText -eq 'false') {
        return 'the task is disabled'
    }
    return ''
}

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
    $arg = '/d /c ""' + $BinPath + '" -config "' + $Config + '" >> "' + $LogPath + '" 2>&1"'
    $action    = New-ScheduledTaskAction -Execute $Cmd -Argument $arg
    $startup   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew

    $registered = $false
    $lastError = ''
    foreach ($span in @([TimeSpan]::MaxValue, (New-TimeSpan -Days 3650))) {
        try {
            $repeat = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
                -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration $span
            Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action `
                -Trigger @($startup, $repeat) -Principal $principal -Settings $settings -Force | Out-Null
            $registered = $true
            break
        } catch {
            $lastError = $_.Exception.Message
        }
    }
    if (-not $registered) { Die ('could not register the task with a one-minute repeating trigger: ' + $lastError) }

    $problem = Get-KeepAliveProblem ([string](Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath))
    if ($problem) { Die ('the registered task has no working keep-alive: ' + $problem) }
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

    $ver = ''
    try { $ver = (& $src -version 2>$null | Out-String).Trim() } catch { $ver = '' }
    if (-not $ver) { Die "$src does not run here: wrong CPU architecture?" }
    $script:ProbeBin = $src

    if ((Test-Healthy) -and -not (Test-Running)) {
        Die ("something already answers on $(Get-HookUrl): probably a user-scope ambitd. " +
             'Remove it first with .\scripts\dev-local.ps1 -Uninstall')
    }

    New-DataDir
    $hadTask = (Get-TaskState) -ne 'not registered'
    try {
        Stop-Ambitd
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        Copy-Item -LiteralPath $src -Destination $BinPath -Force
    } catch {
        $why = $_.Exception.Message
        if ($hadTask) {
            Enable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue | Out-Null
            Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
            Say 'the upgrade failed; the previous task was re-enabled so the endpoint is not left unobserved'
        }
        Die ('upgrade failed: ' + $why)
    }
    Say "installed $BinPath ($ver)"

    Register-AmbitdTask
    if (-not (Wait-Healthy)) {
        Die "the task did not come up on $(Get-HookUrl); see $LogPath and Get-ScheduledTaskInfo -TaskPath '$TaskPath' -TaskName $TaskName"
    }
    Say "task running, health endpoint answers on $(Get-HookUrl)"

    Install-ManagedSettings
    Say "done. Data: $DataDir. Start a Claude Code session and send one prompt: events.jsonl there should gain a prompt_submit line."
    Say 'A session_start line is not expected: that event does not reach ambitd over the http hook (README, Known limitations).'
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
    if ((Get-TaskState) -ne 'not registered') {
        $p = Get-KeepAliveProblem ([string](Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath))
        if ($p) { Write-Host ("keep-alive:       NOT in place: " + $p) }
        else { Write-Host 'keep-alive:       ok (boot trigger, one-minute repeat, IgnoreNew)' }
    }
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

if ($MyInvocation.InvocationName -eq '.') { return }

if ($Purge -and -not $Uninstall) { Die '-Purge only goes with -Uninstall' }
if ($Status) { Show-Status }
elseif ($Uninstall) { Invoke-Uninstall }
else { Invoke-Install }
