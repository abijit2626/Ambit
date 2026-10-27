[CmdletBinding()]
param(
    [string]$Url = '',
    [string]$Timeout = '150',
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$ProgramFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } elseif ($env:ProgramFiles) { $env:ProgramFiles } else { '' }
$ProgramData  = if ($env:ProgramData) { $env:ProgramData } else { '' }
$BinPath = if ($ProgramFiles) { Join-Path (Join-Path $ProgramFiles 'ambit') 'ambitd.exe' } else { '' }
$Config  = if ($ProgramData) { Join-Path (Join-Path $ProgramData 'ambit') 'config.json' } else { '' }

function Say([string]$msg) { Write-Host "verify-restart: $msg" }
function Fail([string]$msg) { [Console]::Error.WriteLine("verify-restart: $msg"); exit 1 }

function Usage {
    [Console]::Error.WriteLine(@'
Kill ambitd and time how long it takes to come back. This is the check the cohort checklist asks
for before a rollout (blocker 2). On Windows the way back is the scheduled task's repeating
one-minute trigger, so expect something under a minute or two, not an instant.

  .\scripts\verify-restart.ps1                 # kill once, wait up to 150 s
  .\scripts\verify-restart.ps1 -Timeout 90     # fail if it takes longer than 90 s
  .\scripts\verify-restart.ps1 -Url http://127.0.0.1:7777

Run it from an Administrator PowerShell on a test machine, not on a volunteer's. It ends the
process outright (Stop-Process -Force), the way a crash does, so the next run reports the stop as
unclean, which is the point. It does not use Stop-ScheduledTask, which would test something else.

Passes when a different ambitd process is running and its health endpoint answers. A process that
comes back is not enough, because a daemon that starts and cannot serve is still unobserved.
Exit status 0 on a pass, 1 on a failure, 2 on a usage error.

Linux and macOS: scripts/verify-restart.sh.
'@)
    exit 2
}

if ($Help) { Usage }
$seconds = 0
if (-not [int]::TryParse($Timeout, [ref]$seconds) -or $seconds -le 0) {
    [Console]::Error.WriteLine("-Timeout takes whole seconds greater than zero, got '$Timeout'")
    Usage
}

function Get-HookUrl {
    if ($Url) { return $Url.TrimEnd('/') }
    $addr = ''
    if ($BinPath -and (Test-Path -LiteralPath $BinPath)) {
        try {
            $json = (& $BinPath -config $Config -print-config 2>$null | Out-String)
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

# Windows has no zombies. PowerShell 7 on Linux or macOS does list a killed process until its
# parent reaps it, and HasExited does not say so, which is how this script is tested off Windows.
function Test-Zombie([int]$id) {
    if ($PSVersionTable.PSEdition -ne 'Core' -or $IsWindows) { return $false }
    $st = (& ps -o stat= -p $id 2>$null | Out-String).Trim()
    return $st.StartsWith('Z')
}

# A process that has exited can still be listed for a moment; only count live ones.
function Get-Live {
    return @(Get-Process -Name ambitd -ErrorAction SilentlyContinue | Where-Object { -not $_.HasExited -and -not (Test-Zombie $_.Id) })
}

$before = @(Get-Live)
if ($before.Count -eq 0) { Fail 'no ambitd process is running' }
if ($before.Count -gt 1) {
    Fail ('more than one ambitd is running (' + (($before | ForEach-Object { $_.Id }) -join ' ') + '); stop the extra one first so the result means something')
}
$old = $before[0].Id
if (-not (Test-Healthy)) { Fail "ambitd (pid $old) is running but $(Get-HookUrl)/healthz does not answer; fix that before testing a restart" }

Say "ending ambitd pid $old"
$watch = [Diagnostics.Stopwatch]::StartNew()
try {
    Stop-Process -Id $old -Force
} catch {
    Fail "could not end pid ${old}: run from an Administrator PowerShell"
}

while ($true) {
    $now = @(Get-Live)
    $elapsed = [int][math]::Floor($watch.Elapsed.TotalSeconds)
    $fresh = @($now | Where-Object { $_.Id -ne $old })
    if ($fresh.Count -eq 1 -and (Test-Healthy)) {
        Say "PASS: back as pid $($fresh[0].Id), health endpoint answering, after ${elapsed}s"
        exit 0
    }
    if ($elapsed -ge $seconds) {
        if ($fresh.Count -ge 1) {
            Fail "FAIL: a new ambitd (pid $($fresh[0].Id)) is running but $(Get-HookUrl)/healthz did not answer within ${seconds}s"
        }
        Fail "FAIL: ambitd did not come back within ${seconds}s; check Get-ScheduledTask -TaskName ambitd -TaskPath \ambit\ for its trigger"
    }
    Start-Sleep -Milliseconds 500
}
