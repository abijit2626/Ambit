[CmdletBinding()]
param(
    [string]$Binary = '.\bin\ambitd.exe',
    [int]$HookPort = 17777,
    [int]$OtlpPort = 14318
)

$ErrorActionPreference = 'Stop'
$script:failures = 0

function Assert($cond, $message) {
    if ($cond) { Write-Host "  ok:   $message" } else { Write-Host "  FAIL: $message"; $script:failures++ }
}

function Test-NoBom($path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    return -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

$devLocal = Join-Path $PSScriptRoot 'dev-local.ps1'
$Binary = (Resolve-Path $Binary).Path
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('ambit-devlocal-' + [guid]::NewGuid().ToString('N'))
$ambitDir = Join-Path $tmp 'ambit dir'
$settings = Join-Path $tmp 'claude home\settings.json'
New-Item -ItemType Directory -Path (Split-Path -Parent $settings) | Out-Null

$seed = @'
{
  "model": "opus",
  "permissions": { "allow": ["Bash(ls)"] },
  "env": { "FOO": "bar" },
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "echo hi" } ] }
    ]
  }
}
'@
[System.IO.File]::WriteAllText($settings, $seed, (New-Object System.Text.UTF8Encoding($false)))

$common = @{ AmbitDir = $ambitDir; ClaudeSettings = $settings; Binary = $Binary; HookPort = $HookPort; OtlpPort = $OtlpPort }
$hookUrl = "http://127.0.0.1:$HookPort/hook"

try {
    Write-Host '1. install'
    & $devLocal @common | Out-Null
    $j = [System.IO.File]::ReadAllText($settings) | ConvertFrom-Json

    Assert (Test-NoBom $settings) 'settings.json has no byte order mark'
    Assert (Test-NoBom (Join-Path $ambitDir 'config.json')) 'config.json has no byte order mark (Go cannot parse one)'
    Assert ($j.model -eq 'opus') 'an unrelated setting survived'
    Assert ($j.permissions.allow[0] -eq 'Bash(ls)') 'an existing permission array survived'
    Assert ($j.env.FOO -eq 'bar') 'an existing env var survived'
    Assert ($j.env.OTEL_EXPORTER_OTLP_ENDPOINT -eq "http://127.0.0.1:$OtlpPort") 'OTel endpoint set to the OTLP/HTTP port'
    Assert ($j.env.OTEL_EXPORTER_OTLP_PROTOCOL -eq 'http/json') 'OTel protocol is http/json'
    $pre = @($j.hooks.PreToolUse)
    Assert ($pre.Count -eq 2) 'PreToolUse keeps the existing entry and adds one'
    Assert ($pre[0].hooks[0].command -eq 'echo hi') 'the existing hook is untouched and still first'
    Assert ($pre[1].hooks[0].url -eq $hookUrl) 'the ambitd hook is an http hook on the configured port'
    Assert ($null -eq $j.hooks.UserPromptSubmit[0].matcher) 'UserPromptSubmit has no matcher, which that event does not support'

    $events = @('PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionRequest', 'PermissionDenied',
        'SessionStart', 'SessionEnd', 'UserPromptSubmit', 'InstructionsLoaded', 'ConfigChange',
        'SubagentStart', 'SubagentStop', 'PreCompact', 'PostCompact')
    $missing = @($events | Where-Object {
            $n = 0
            foreach ($e in @($j.hooks.$_)) { foreach ($h in @($e.hooks)) { if ($h.url -eq $hookUrl) { $n++ } } }
            $n -ne 1
        })
    Assert ($missing.Count -eq 0) "every one of the $($events.Count) events has exactly one ambitd hook ($($missing -join ', '))"

    Assert ((Get-Content (Join-Path $ambitDir 'config.json') -Raw | ConvertFrom-Json).hook_addr -eq "127.0.0.1:$HookPort") 'config.json parses and carries the hook address'
    $h = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$HookPort/healthz"
    Assert ($h.StatusCode -eq 200) 'ambitd is up and healthy'

    $body = '{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"C:\\Users\\dev","tool_name":"Read","tool_input":{"file_path":"C:\\Users\\dev\\.ssh\\id_rsa"}}'
    $r = Invoke-WebRequest -UseBasicParsing -Method Post -ContentType 'application/json' -Body $body -Uri $hookUrl
    Assert ($r.Content.Trim() -eq '{}') 'the hook answers {} (inert)'

    Write-Host '2. install again'
    & $devLocal @common | Out-Null
    $j2 = [System.IO.File]::ReadAllText($settings) | ConvertFrom-Json
    Assert (@($j2.hooks.PreToolUse).Count -eq 2) 're-running does not stack duplicate hooks'
    Assert ([System.IO.File]::ReadAllText("$settings.ambit-backup") -eq $seed) 'the backup is still the pristine original, not the modified file'

    Write-Host '3. status'
    Start-Sleep -Milliseconds 1500
    $out = (& $devLocal @common -Status 6>&1 | Out-String)
    Assert ($out -match 'ambitd local status') '-Status prints its header'
    Assert ($out -match 'process:\s+running') '-Status sees the running process'
    Assert ($out -notmatch 'LEAKED') '-Status reports no leak in the Wazuh-bound sink'

    Write-Host '4. uninstall'
    & $devLocal @common -Uninstall | Out-Null
    Assert ([System.IO.File]::ReadAllText($settings) -eq $seed) 'settings.json is restored byte for byte'
    Start-Sleep -Milliseconds 500
    $still = @(Get-Process -Name ambitd -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $ambitDir 'ambitd.exe') })
    Assert ($still.Count -eq 0) 'ambitd is stopped'
    Assert (Test-Path (Join-Path $ambitDir 'config.json')) 'collected data and config are left in place'
} finally {
    Get-Process -Name ambitd -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like "$tmp*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failures -eq 0) { Write-Host 'dev-local-test: PASS' } else { Write-Host "dev-local-test: FAIL ($($script:failures))" }
exit $script:failures
