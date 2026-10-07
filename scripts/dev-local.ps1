<#
.SYNOPSIS
Set up ambitd against your own Claude Code sessions, on your own Windows machine.

.DESCRIPTION
The Windows counterpart of dev-local.sh.

Why: the M0 exit criterion that blocks everything downstream is the MEASURED
INTERESTING FRACTION - what share of real tool calls are security-relevant enough
to cross to Wazuh. The design estimates 2-5%. If your real work comes back at 30%,
the filter criteria in docs/04-data-model.md tighten before M1. You are the cheapest
source of that number: this needs no Wazuh, no MDM and no cohort.

This uses USER-SCOPE settings (%USERPROFILE%\.claude\settings.json), not managed
settings. Nothing here is machine-wide and nothing needs admin. It is safe because
ambitd is inert: every hook response is {}, which means "no opinion", so Claude Code's
permission pipeline behaves exactly as it would with no hook installed.

.PARAMETER Status
Show what has been collected so far, including the interesting fraction.

.PARAMETER Uninstall
Stop ambitd and restore your original settings.json.

.PARAMETER Binary
Use a prebuilt ambitd.exe instead of building one with Go.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1 -Status
#>
[CmdletBinding()]
param(
    [switch]$Status,
    [switch]$Uninstall,
    [string]$Binary = '',
    [int]$HookPort = $(if ($env:HOOK_PORT) { [int]$env:HOOK_PORT } else { 7777 }),
    [int]$OtlpPort = $(if ($env:OTLP_PORT) { [int]$env:OTLP_PORT } else { 4318 }),
    [string]$AmbitDir = $(if ($env:AMBIT_DIR) { $env:AMBIT_DIR } else { Join-Path $env:USERPROFILE '.ambit' }),
    [string]$ClaudeSettings = $(
        if ($env:CLAUDE_SETTINGS) { $env:CLAUDE_SETTINGS }
        elseif ($env:CLAUDE_CONFIG_DIR) { Join-Path $env:CLAUDE_CONFIG_DIR 'settings.json' }
        else { Join-Path $env:USERPROFILE '.claude\settings.json' }
    )
)

# This file is ASCII on purpose. Windows PowerShell 5.1 reads a script without a byte
# order mark as the system code page, so a single typographic dash would corrupt a
# string literal.

$ErrorActionPreference = 'Stop'

$Root       = Split-Path -Parent $PSScriptRoot
$Config     = Join-Path $AmbitDir 'config.json'
$Events     = Join-Path $AmbitDir 'events.jsonl'
$Trajectory = Join-Path $AmbitDir 'trajectory.jsonl'
$Bin        = Join-Path $AmbitDir 'ambitd.exe'
$Backup     = "$ClaudeSettings.ambit-backup"
$HookUrl    = "http://127.0.0.1:$HookPort/hook"

function Write-Bold($text) { Write-Host $text -ForegroundColor White }
function Write-Warn($text) { Write-Host $text -ForegroundColor Yellow }

# Windows PowerShell 5.1's Set-Content -Encoding UTF8 writes a byte order mark, which
# Go's encoding/json rejects ("invalid character 'i' looking for beginning of value").
# ambitd reads this config and Claude Code reads settings.json, so neither file may
# have one.
function Write-TextNoBom($path, $text) {
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# ConvertFrom-Json returns PSCustomObject trees, which cannot be edited in place the way
# the JSON they came from can. This turns them into ordered dictionaries and arrays so
# the merge below behaves identically on Windows PowerShell 5.1 and PowerShell 7.
function ConvertTo-Plain($o) {
    if ($null -eq $o) { return $null }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-Plain $p.Value }
        return $h
    }
    if ($o -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $o.Keys) { $h[$k] = ConvertTo-Plain $o[$k] }
        return $h
    }
    if (($o -is [System.Collections.IEnumerable]) -and ($o -isnot [string])) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $o) { [void]$list.Add((ConvertTo-Plain $i)) }
        return , $list.ToArray()
    }
    return $o
}

function Get-AmbitProcess {
    Get-Process -Name 'ambitd' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Bin }
}

function Test-Healthy {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri "http://127.0.0.1:$HookPort/healthz"
        return ($r.StatusCode -eq 200)
    } catch {
        return $false
    }
}

# --- status -------------------------------------------------------------------

function Show-Status {
    Write-Bold 'ambitd local status'
    Write-Host ''
    $proc = Get-AmbitProcess | Select-Object -First 1
    if ($proc) { Write-Host "  process:    running (pid $($proc.Id))" } else { Write-Host '  process:    not running' }
    Write-Host "  config:     $Config"

    if (-not (Test-Path $Trajectory)) {
        Write-Host '  collected:  nothing yet'
        return
    }

    # One pass over the spool, matching the two top-level fields with a pattern rather
    # than parsing every line: `source` and `kind` come first in the rich schema, ahead
    # of every nested object, so the first match is the top-level value. A full parse of
    # a day of events would take minutes.
    $total = 0
    $kinds = @{}
    $sources = @{}
    $toolTotal = 0
    $reKind = [regex]'"kind":"([^"]*)"'
    $reSource = [regex]'"source":"([^"]*)"'
    foreach ($line in [System.IO.File]::ReadLines($Trajectory)) {
        if ($line.Length -eq 0) { continue }
        $total++
        $k = $reKind.Match($line); $s = $reSource.Match($line)
        $kind = if ($k.Success) { $k.Groups[1].Value } else { '?' }
        $src = if ($s.Success) { $s.Groups[1].Value } else { '?' }
        if ($kinds.ContainsKey($kind)) { $kinds[$kind]++ } else { $kinds[$kind] = 1 }
        if ($sources.ContainsKey($src)) { $sources[$src]++ } else { $sources[$src] = 1 }
        # Only HOOK-sourced tool events count toward the fraction. OTel records also map
        # to tool kinds, and counting them would inflate the denominator with the same
        # tool calls observed a second time by the corroborating stream.
        if (($kind -eq 'tool_pre' -or $kind -eq 'tool_post') -and $src -eq 'hook') { $toolTotal++ }
    }

    $crossed = 0
    $toolCrossed = 0
    $reasons = @{}
    if (Test-Path $Events) {
        foreach ($line in [System.IO.File]::ReadLines($Events)) {
            if ($line.Length -eq 0) { continue }
            $crossed++
            try { $d = $line | ConvertFrom-Json } catch { continue }
            if ($d.kind -ne 'tool_pre' -and $d.kind -ne 'tool_post') { continue }
            $toolCrossed++
            # Infer why, in the same order the filter decides.
            $why = 'sampled_or_other'
            if ($d.policy_decision) { $why = 'policy_decision' }
            elseif ($d.prov_edge_count) { $why = 'provenance_edge' }
            elseif ($d.path_zone -eq 'credential' -or $d.path_zone -eq 'system') { $why = 'severe_zone' }
            elseif ($d.secret_hit_kinds) { $why = 'secret_hit' }
            elseif ($d.bash_command_class -eq 'network' -or $d.bash_command_class -eq 'publish' -or $d.bash_command_class -eq 'vcs_write') { $why = 'network_command' }
            elseif ($d.tool_mcp_server) { $why = 'mcp_risk' }
            elseif ($d.prov_fp_notable) { $why = 'notable_fingerprint' }
            if ($reasons.ContainsKey($why)) { $reasons[$why]++ } else { $reasons[$why] = 1 }
        }
    }

    Write-Host "  spool:      $total events ($Trajectory)"
    Write-Host "  crossed:    $crossed events ($Events)"
    if ($total -gt 0) { Write-Host ('  fraction:   {0:N2}% of all events crossed' -f (($crossed / $total) * 100)) }

    Write-Host ''
    Write-Host "  TOOL EVENTS (the number the design's 2-5% estimate is about)"
    if ($toolTotal -gt 0) {
        $pct = $toolCrossed / $toolTotal * 100
        Write-Host ('    {0} of {1} crossed = {2:N2}%' -f $toolCrossed, $toolTotal, $pct)
        if ($pct -gt 10) {
            Write-Host '    ^ well above the 2-5% estimate. The filter criteria in'
            Write-Host '      docs/04-data-model.md need tightening before M1.'
        } elseif ($toolTotal -lt 500) {
            Write-Host '    ^ small sample. Keep it running for a full day of real work.'
        }
    } else {
        Write-Host '    no tool events yet'
    }

    if ($reasons.Count -gt 0) {
        Write-Host ''
        Write-Host '  WHY THEY CROSSED'
        $reasons.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { Write-Host ('    {0,-24} {1}' -f $_.Key, $_.Value) }
    }

    Write-Host ''
    Write-Host '  STREAMS (both non-zero once OTel is flowing; exactly one'
    Write-Host '   silent is the D7 discrepancy)'
    $sources.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { Write-Host ('    {0,-24} {1}' -f $_.Key, $_.Value) }

    Write-Host ''
    Write-Host '  ALL EVENT KINDS'
    $kinds.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { Write-Host ('    {0,-24} {1}' -f $_.Key, $_.Value) }

    # The sink stores paths as keyed digests, so none of these may appear. JSON escapes
    # a backslash as two, so the profile path is checked in both spellings.
    Write-Host ''
    Write-Host '  Leak check on the Wazuh-bound sink (should all be clean):'
    $profilePath = $env:USERPROFILE
    $needles = @($profilePath, $profilePath.Replace('\', '\\'), $profilePath.Replace('\', '/'), '.ssh', '.aws', 'AppData')
    foreach ($n in $needles) {
        if ((Test-Path $Events) -and (Select-String -Path $Events -SimpleMatch -Pattern $n -Quiet)) {
            Write-Warn "    LEAKED: $n"
        } else {
            Write-Host "    clean:  $n"
        }
    }
}

# --- uninstall ----------------------------------------------------------------

function Invoke-Uninstall {
    Write-Bold 'Removing the local ambitd setup'
    Get-AmbitProcess | Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path $Backup) {
        Move-Item -Force $Backup $ClaudeSettings
        Write-Host "  restored $ClaudeSettings from backup"
    } else {
        Write-Warn "  no backup found; remove the ambit hooks from $ClaudeSettings by hand"
    }
    Write-Host ''
    Write-Host '  Left in place so you do not lose collected data:'
    Write-Host "    $AmbitDir"
    Write-Host '  Delete it when you are done:'
    Write-Host "    Remove-Item -Recurse -Force '$AmbitDir'"
}

if ($Status) { Show-Status; return }
if ($Uninstall) { Invoke-Uninstall; return }

# --- install ------------------------------------------------------------------

# Creating the directory ourselves means ambitd will find it already there and leave
# its permissions alone, so this script has to make it private. Under the default
# %USERPROFILE% it already is; AMBIT_DIR can point anywhere, and the spool holds prompt
# text. SYSTEM and Administrators keep access so a Wazuh agent (which runs as SYSTEM)
# can tail events.jsonl.
if (-not (Test-Path $AmbitDir)) {
    New-Item -ItemType Directory -Path $AmbitDir | Out-Null
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $AmbitDir /inheritance:r /grant:r "*${me}:(OI)(CI)F" '/grant:r' '*S-1-5-18:(OI)(CI)F' '/grant:r' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not restrict $AmbitDir with icacls (exit $LASTEXITCODE)" }
}

Write-Bold 'Building ambitd'
# A running ambitd.exe is locked and cannot be overwritten, so stop it before the build.
Get-AmbitProcess | Stop-Process -Force -ErrorAction SilentlyContinue
if ($Binary) {
    if (-not (Test-Path $Binary)) { throw "-Binary $Binary does not exist" }
    Copy-Item -Force $Binary $Bin
} else {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'Go was not found on PATH. Install Go 1.24 or newer from https://go.dev/dl/, or pass -Binary with a prebuilt ambitd.exe.'
    }
    Push-Location $Root
    try {
        & go build -ldflags '-X main.version=dev-local' -o $Bin ./cmd/ambitd
        if ($LASTEXITCODE -ne 0) { throw "go build failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}
Write-Host "  $Bin"

Write-Bold 'Writing config'
# home is detected by ambitd; trusted_repo_paths marks which CLAUDE.md files are
# expected, so an instruction file from anywhere else shows up as a D8 candidate.
#
# baseline_dir is under $AmbitDir deliberately. mcp-interpose runs as you, not as a
# service, so a baseline store under ProgramData would be unwritable and every listing
# would report as degraded rather than compared. This script does not touch .mcp.json:
# wrapping a server is a deliberate edit you make yourself. See the README for the
# .mcp.json shape.
$hostSlug = ($env:COMPUTERNAME -replace '[^A-Za-z0-9]', '').ToLower()
if ($hostSlug.Length -gt 16) { $hostSlug = $hostSlug.Substring(0, 16) }
$cfg = [ordered]@{
    hook_addr            = "127.0.0.1:$HookPort"
    otlp_addr            = "127.0.0.1:$OtlpPort"
    otlp_enabled         = $true
    events_path          = $Events
    trajectory_path      = $Trajectory
    fingerprint_key_path = (Join-Path $AmbitDir 'fingerprint.key')
    baseline_dir         = (Join-Path $AmbitDir 'baselines')
    endpoint_id          = "ep_$hostSlug"
    user_id              = $env:USERNAME
    org_id               = 'local'
    trusted_repo_paths   = @((Join-Path $env:USERPROFILE 'src'), $Root)
    trusted_mcp_servers  = @()
    sample_rate          = 0.005
    health_seconds       = 60
    latency_budget_ms    = 5
    enforce              = $false
}
Write-TextNoBom $Config (ConvertTo-Json -InputObject $cfg -Depth 5)
Write-Host "  $Config"

Write-Bold "Merging hooks into $ClaudeSettings"
$settingsDir = Split-Path -Parent $ClaudeSettings
if (-not (Test-Path $settingsDir)) { New-Item -ItemType Directory -Path $settingsDir | Out-Null }
if (-not (Test-Path $ClaudeSettings)) { Write-TextNoBom $ClaudeSettings '{}' }

# Never overwrite an existing backup. Re-running this script would otherwise replace
# the pristine copy with an already-modified one, and -Uninstall would then "restore"
# settings that still contain the hooks.
if (Test-Path $Backup) {
    Write-Host "  backup already exists, keeping it: $Backup"
} else {
    Copy-Item $ClaudeSettings $Backup
    Write-Host "  backed up to $Backup"
}

$raw = [System.IO.File]::ReadAllText($ClaudeSettings)
if ([string]::IsNullOrWhiteSpace($raw)) { $raw = '{}' }
$settings = ConvertTo-Plain ($raw | ConvertFrom-Json)
if ($null -eq $settings) { $settings = [ordered]@{} }

# Events with no matcher support take a bare hooks list.
$noMatcher = @('UserPromptSubmit')
$events = @(
    'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
    'PermissionRequest', 'PermissionDenied',
    'SessionStart', 'SessionEnd', 'UserPromptSubmit',
    'InstructionsLoaded', 'ConfigChange',
    'SubagentStart', 'SubagentStop', 'PreCompact', 'PostCompact'
)

if (-not $settings.Contains('hooks') -or $null -eq $settings['hooks']) { $settings['hooks'] = [ordered]@{} }
$hooks = $settings['hooks']
foreach ($ev in $events) {
    $existing = New-Object System.Collections.ArrayList
    if ($hooks.Contains($ev) -and $null -ne $hooks[$ev]) {
        foreach ($e in @($hooks[$ev])) { [void]$existing.Add($e) }
    }
    # Idempotent: do not stack duplicate entries on re-run.
    $already = $false
    foreach ($e in $existing) {
        if ($e -is [System.Collections.IDictionary] -and $e.Contains('hooks')) {
            foreach ($h in @($e['hooks'])) {
                if ($h -is [System.Collections.IDictionary] -and $h['url'] -eq $HookUrl) { $already = $true }
            }
        }
    }
    if (-not $already) {
        $entry = [ordered]@{ type = 'http'; url = $HookUrl }
        if ($noMatcher -contains $ev) {
            $block = [ordered]@{ hooks = @($entry) }
        } else {
            $block = [ordered]@{ matcher = '.*'; hooks = @($entry) }
        }
        [void]$existing.Add($block)
    }
    $hooks[$ev] = $existing.ToArray()
}

if (-not $settings.Contains('env') -or $null -eq $settings['env']) { $settings['env'] = [ordered]@{} }
$envBlock = $settings['env']
$envBlock['CLAUDE_CODE_ENABLE_TELEMETRY'] = '1'
$envBlock['OTEL_METRICS_EXPORTER'] = 'otlp'
$envBlock['OTEL_LOGS_EXPORTER'] = 'otlp'
# http/json, not grpc or http/protobuf: ambitd's receiver decodes OTLP/JSON with the
# standard library. Port 4318 is OTLP/HTTP; 4317 is gRPC.
$envBlock['OTEL_EXPORTER_OTLP_PROTOCOL'] = 'http/json'
$envBlock['OTEL_EXPORTER_OTLP_ENDPOINT'] = "http://127.0.0.1:$OtlpPort"

Write-TextNoBom $ClaudeSettings ((ConvertTo-Json -InputObject $settings -Depth 20) + "`n")
Write-Host "  added $($events.Count) hook events + OTel env"

Write-Bold 'Starting ambitd'
$logOut = Join-Path $AmbitDir 'ambitd.out.log'
$logErr = Join-Path $AmbitDir 'ambitd.log'
# Quotes are added by hand: Start-Process joins -ArgumentList with spaces and does not
# quote, so a profile path containing a space would otherwise split into two arguments.
$null = Start-Process -FilePath $Bin -ArgumentList @('-config', "`"$Config`"") `
    -WindowStyle Hidden -RedirectStandardOutput $logOut -RedirectStandardError $logErr -PassThru

$up = $false
for ($i = 0; $i -lt 50; $i++) {
    if (Test-Healthy) { $up = $true; break }
    Start-Sleep -Milliseconds 100
}
if ($up) {
    Write-Host "  running, hook endpoint healthy on 127.0.0.1:$HookPort"
} else {
    Write-Warn "  ambitd did not come up; see $logErr"
    if (Test-Path $logErr) { Get-Content $logErr -Tail 20 }
    Write-Warn '  If the error is about the address, Windows may have reserved the port. Check with:'
    Write-Warn '    netsh interface ipv4 show excludedportrange protocol=tcp'
    Write-Warn '  then re-run with a different -HookPort (and update nothing else: the script rewrites the hook URL).'
    exit 1
}

Write-Host @"

Done. Now just work normally.

Start Claude Code sessions and use them as you always would. ambitd returns no
decision, so nothing about those sessions changes. Restart any Claude Code session that
was already open: hooks are read when a session starts. After a day of real work:

    powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1 -Status

That prints the interesting fraction over tool events, which is the M0 exit
criterion, plus why each event crossed so you can see which criterion drives the
volume.

Notes:

  - ambitd does not restart itself. After a reboot, re-run this script.
  - The spool ($Trajectory) holds everything, including prompt text. It lives in
    a directory only you, SYSTEM and Administrators can open, and never leaves the
    machine.
  - The Wazuh-bound sink ($Events) holds only the filtered slice, with paths as
    keyed digests. -Status leak-checks it.
  - Claude Code on Windows can run commands through Git Bash or through its PowerShell
    tool; ambitd classifies both.
  - To remove:  powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1 -Uninstall

"@
