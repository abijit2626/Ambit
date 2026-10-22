package service

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
)

const (
	unitFile  = "ambitd.service"
	plistFile = "com.ambit.ambitd.plist"
	shScript  = "../../scripts/install-system.sh"
	psScript  = "../../scripts/install-system.ps1"
	bundle    = "../claude-code/managed-settings.m0.json"
	scaUnix   = "../wazuh/sca/ambit_managed_settings_m0.yml"
	scaWin    = "../wazuh/sca/ambit_managed_settings_windows_m0.yml"

	binPath      = "/usr/local/bin/ambitd"
	linuxConfig  = "/etc/ambit/config.json"
	darwinConfig = "/usr/local/etc/ambit/config.json"
	label        = "com.ambit.ambitd"
)

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func unit(t *testing.T, text string) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
			out[section] = map[string]string{}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || section == "" {
				t.Fatalf("unparseable unit line %q", line)
			}
			out[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func TestSystemdUnitStartsAtBootAndNeverStopsRestarting(t *testing.T) {
	u := unit(t, read(t, unitFile))
	want := []struct{ section, key, value string }{
		{"Service", "ExecStart", binPath + " -config " + linuxConfig},
		{"Service", "Restart", "always"},
		{"Unit", "StartLimitIntervalSec", "0"},
		{"Install", "WantedBy", "multi-user.target"},
	}
	for _, w := range want {
		if got := u[w.section][w.key]; got != w.value {
			t.Errorf("[%s] %s = %q, want %q", w.section, w.key, got, w.value)
		}
	}
	if _, ok := u["Service"]["User"]; ok {
		t.Error("the unit sets User=; ambitd runs as root so it can keep /var/lib/ambit private and readable by the Wazuh agent")
	}
}

func TestSystemdUnitPassesSystemdAnalyze(t *testing.T) {
	sa, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not installed")
	}

	text := regexp.MustCompile(`(?m)^ExecStart=\S+`).ReplaceAllString(read(t, unitFile), "ExecStart=/bin/true")
	tmp := filepath.Join(t.TempDir(), unitFile)
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(sa, "verify", tmp).CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) > 0 {
		t.Errorf("systemd-analyze verify: err=%v\n%s", err, out)
	}
}

func plist(t *testing.T, text string) map[string]any {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.Strict = false
	out := map[string]any{}
	key := ""
	var arr []string
	inArray := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch e := tok.(type) {
		case xml.StartElement:
			switch e.Name.Local {
			case "key":
				var s string
				if err := dec.DecodeElement(&s, &e); err != nil {
					t.Fatal(err)
				}
				key = s
			case "string", "integer":
				var s string
				if err := dec.DecodeElement(&s, &e); err != nil {
					t.Fatal(err)
				}
				if inArray {
					arr = append(arr, s)
				} else {
					out[key] = s
				}
			case "true", "false":
				out[key] = e.Name.Local == "true"
			case "array":
				inArray, arr = true, nil
			}
		case xml.EndElement:
			if e.Name.Local == "array" {
				out[key] = arr
				inArray = false
			}
		}
	}
	return out
}

func TestLaunchDaemonStartsAtBootAndIsKeptAlive(t *testing.T) {
	p := plist(t, read(t, plistFile))
	if p["Label"] != label {
		t.Errorf("Label = %v, want %s", p["Label"], label)
	}
	args, _ := p["ProgramArguments"].([]string)
	if strings.Join(args, " ") != binPath+" -config "+darwinConfig {
		t.Errorf("ProgramArguments = %v", args)
	}
	for _, k := range []string{"RunAtLoad", "KeepAlive"} {
		if p[k] != true {
			t.Errorf("%s = %v, want true", k, p[k])
		}
	}
	if _, ok := p["UserName"]; ok {
		t.Error("the plist sets UserName; a LaunchDaemon runs as root, which ambitd needs")
	}
}

func TestShellInstallerAgreesWithTheDefinitions(t *testing.T) {
	sh := read(t, shScript)
	for _, want := range []string{
		"BIN_PATH=" + binPath,
		"CONFIG=" + linuxConfig,
		"CONFIG=" + darwinConfig,
		"LABEL=" + label,
		"UNIT_DST=/etc/systemd/system/" + unitFile,
		"UNIT_DST=/Library/LaunchDaemons/$LABEL.plist",
		`UNIT_SRC="$ROOT/deploy/service/` + unitFile + `"`,
		`UNIT_SRC="$ROOT/deploy/service/$LABEL.plist"`,
	} {
		if !strings.Contains(sh, want) {
			t.Errorf("install-system.sh does not contain %q", want)
		}
	}
	if runtime.GOOS == "linux" {
		def := filepath.Dir(config.Default().EventsPath)
		if !strings.Contains(sh, "DATA_DIR="+def) {
			t.Errorf("install-system.sh's Linux DATA_DIR is not ambitd's default %s", def)
		}
	}
}

func TestShellInstallerParses(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if out, err := exec.Command(bash, "-n", shScript).CombinedOutput(); err != nil {
		t.Errorf("bash -n: %v\n%s", err, out)
	}
}

func TestPowerShellInstallerKeepsTheTaskAlive(t *testing.T) {
	ps := read(t, psScript)
	for _, want := range []string{
		"New-ScheduledTaskTrigger -AtStartup",
		"-UserId 'SYSTEM' -LogonType ServiceAccount",
		"-ExecutionTimeLimit ([TimeSpan]::Zero)",
		"-RestartCount 999",
		"-RestartInterval (New-TimeSpan -Minutes 1)",
		"/setowner",
		"/inheritance:r",
	} {
		if !strings.Contains(ps, want) {
			t.Errorf("install-system.ps1 does not contain %q", want)
		}
	}
}

func functionBody(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "function "+name+" ")
	if start < 0 {
		start = strings.Index(script, "function "+name+"(")
	}
	if start < 0 {
		t.Fatalf("install-system.ps1 has no function %s", name)
	}
	rest := script[start+len("function "):]
	if end := strings.Index(rest, "\nfunction "); end >= 0 {
		return rest[:end]
	}
	if end := strings.Index(rest, "\nif ($MyInvocation"); end >= 0 {
		return rest[:end]
	}
	return rest
}

func TestPowerShellInstallerRegistersTheKeepAliveItself(t *testing.T) {
	ps := read(t, psScript)
	for _, want := range []string{
		"New-ScheduledTaskTrigger -Once",
		"-RepetitionInterval (New-TimeSpan -Minutes 1)",
		"-MultipleInstances IgnoreNew",
		"Get-KeepAliveProblem",
		"Export-ScheduledTask",
	} {
		if !strings.Contains(ps, want) {
			t.Errorf("install-system.ps1 does not contain %q: the task's restart-on-failure setting did not restart ambitd on a real machine, so the installer must register the repeating trigger that did", want)
		}
	}
	register := functionBody(t, ps, "Register-AmbitdTask")
	if !strings.Contains(register, "-AtStartup") || !strings.Contains(register, "-Once") {
		t.Error("Register-AmbitdTask must register both the boot trigger and the repeating trigger")
	}
}

func TestPowerShellInstallerDisablesTheTaskBeforeReplacingTheBinary(t *testing.T) {
	ps := read(t, psScript)

	stop := functionBody(t, ps, "Stop-Ambitd")
	disable := strings.Index(stop, "Disable-ScheduledTask")
	stopTask := strings.Index(stop, "Stop-ScheduledTask")
	kill := strings.Index(stop, "Stop-Process")
	if disable < 0 || stopTask < 0 || kill < 0 || !(disable < stopTask && stopTask < kill) {
		t.Errorf("Stop-Ambitd must disable the task, then stop it, then stop the process (positions %d, %d, %d): with the repeating trigger in place, a running task is restarted within a minute and the binary copy fails", disable, stopTask, kill)
	}
	if !strings.Contains(stop, "Get-AmbitdProcess") || !strings.Contains(stop, "Start-Sleep") || !strings.Contains(stop, "Die ") {
		t.Error("Stop-Ambitd must wait until the process has exited and fail if it has not, not only ask it to stop")
	}
	if !strings.Contains(functionBody(t, ps, "Get-AmbitdProcess"), "Get-Process") {
		t.Error("Get-AmbitdProcess must look the process up with Get-Process")
	}

	install := functionBody(t, ps, "Invoke-Install")
	stopAt := strings.Index(install, "Stop-Ambitd")
	copyAt := strings.Index(install, "Copy-Item -LiteralPath $src")
	if stopAt < 0 || copyAt < 0 || stopAt > copyAt {
		t.Errorf("Invoke-Install must stop ambitd before it copies the new binary (positions %d, %d)", stopAt, copyAt)
	}
	if !strings.Contains(install, "Enable-ScheduledTask") {
		t.Error("Invoke-Install must re-enable the previous task if the upgrade fails, or the endpoint stays unobserved")
	}

	uninstall := functionBody(t, ps, "Invoke-Uninstall")
	stopAt = strings.Index(uninstall, "Stop-Ambitd")
	unregister := strings.Index(uninstall, "Unregister-ScheduledTask")
	if stopAt < 0 || unregister < 0 || stopAt > unregister {
		t.Errorf("Invoke-Uninstall must stop ambitd before it unregisters the task (positions %d, %d)", stopAt, unregister)
	}
}

func TestInstallersDoNotSendAnOperatorLookingForSessionStart(t *testing.T) {
	for _, path := range []string{psScript, shScript} {
		text := read(t, path)
		if strings.Contains(text, "gains a session_start") {
			t.Errorf("%s tells the operator to look for a session_start line, but SessionStart never reached ambitd in the lab, so a healthy install would look broken", path)
		}
		if !strings.Contains(text, "prompt_submit") {
			t.Errorf("%s does not name an event that does arrive (prompt_submit) as the post-install check", path)
		}
	}
}

func TestKeepAliveCheckAcceptsOnlyTheRightTask(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	dir := t.TempDir()

	task := func(boot, repeat, policy, enabled string) string {
		return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>` + boot + repeat + `
  </Triggers>
  <Settings>` + policy + enabled + `
  </Settings>
</Task>`
	}
	const (
		bootOK   = `<BootTrigger><Enabled>true</Enabled></BootTrigger>`
		repeatOK = `<TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-10-20T10:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>`
		policyOK = `<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>`
		enabled  = `<Enabled>true</Enabled>`
	)
	cases := []struct {
		name, xml, problem string
	}{
		{"boot trigger plus one-minute repeat, IgnoreNew", task(bootOK, repeatOK, policyOK, enabled), ""},
		{"the stock task, boot trigger only", task(bootOK, "", policyOK, enabled), "repeating"},
		{"repeat every five minutes", task(bootOK, strings.Replace(repeatOK, "PT1M", "PT5M", 1), policyOK, enabled), "repeating"},
		{"no boot trigger", task("", repeatOK, policyOK, enabled), "boot"},
		{"parallel instances", task(bootOK, repeatOK, strings.Replace(policyOK, "IgnoreNew", "Parallel", 1), enabled), "MultipleInstances"},
		{"policy missing", task(bootOK, repeatOK, "", enabled), "MultipleInstances"},
		{"task disabled", task(bootOK, repeatOK, policyOK, `<Enabled>false</Enabled>`), "disabled"},
		{"not XML", "this is not xml", "XML"},
	}

	env := append(os.Environ(),
		"ProgramW6432="+dir, "ProgramFiles="+dir, "ProgramData="+dir, "SystemRoot="+dir)
	script, err := filepath.Abs(psScript)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		xmlPath := filepath.Join(dir, "task"+string(rune('a'+i))+".xml")
		if err := os.WriteFile(xmlPath, []byte(c.xml), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command",
			". '"+script+"'; Get-KeepAliveProblem ([System.IO.File]::ReadAllText('"+xmlPath+"'))")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s: pwsh failed: %v\n%s", c.name, err, out)
			continue
		}
		got := strings.TrimSpace(string(out))
		switch {
		case c.problem == "" && got != "":
			t.Errorf("%s: the check rejected a correct task: %q", c.name, got)
		case c.problem != "" && !strings.Contains(got, c.problem):
			t.Errorf("%s: want a problem mentioning %q, got %q", c.name, c.problem, got)
		}
	}
}

func TestStopAmbitdReturnsOnceTheProcessHasExited(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	dir := t.TempDir()
	env := append(os.Environ(),
		"ProgramW6432="+dir, "ProgramFiles="+dir, "ProgramData="+dir, "SystemRoot="+dir)
	script, err := filepath.Abs(psScript)
	if err != nil {
		t.Fatal(err)
	}
	stubs := `
$script:alive = $true
function Get-ScheduledTask { param($TaskName, $TaskPath, $ErrorAction) [pscustomobject]@{ State = 'Running' } }
function Disable-ScheduledTask { param($TaskName, $TaskPath) }
function Stop-ScheduledTask { param($TaskName, $TaskPath, $ErrorAction) }
function Start-Sleep { param($Milliseconds) }
function Get-Process { param($Name, $ErrorAction) if ($script:alive) { [pscustomobject]@{ Path = $BinPath } } }
`
	cases := []struct {
		name, afterKill, want string
	}{
		{"the process exits when killed", "$false", "stopped"},
		{"the process never exits", "$true", "still running"},
	}
	for _, c := range cases {
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command",
			". '"+script+"'"+stubs+
				"function Stop-Process { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject, [switch]$Force) process { $script:alive = "+c.afterKill+" } }\n"+
				"try { Stop-Ambitd; 'stopped' } catch { $_.Exception.Message }")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s: pwsh failed: %v\n%s", c.name, err, out)
			continue
		}
		if got := strings.TrimSpace(string(out)); !strings.Contains(got, c.want) {
			t.Errorf("%s: want %q, got %q; under Set-StrictMode an empty Get-AmbitdProcess result is $null and has no Count, which made the first live upgrade fail after the kill", c.name, c.want, got)
		}
	}
}

func TestPowerShellInstallerWrapsCommandResultsBeforeCount(t *testing.T) {
	unwrapped := regexp.MustCompile(`(^|[^@])\(\s*[A-Z][a-z]+-[A-Za-z]+[^()]*\)\.Count\b`)
	for i, line := range strings.Split(read(t, psScript), "\n") {
		if unwrapped.MatchString(line) {
			t.Errorf("%s:%d reads .Count on a bare command result: %s; wrap it in @() so zero or one result still has a Count under Set-StrictMode", psScript, i+1, strings.TrimSpace(line))
		}
	}
}

func TestPowerShellInstallerIsASCII(t *testing.T) {
	for i, b := range []byte(read(t, psScript)) {
		if b > 0x7f {
			t.Fatalf("install-system.ps1 has a non-ASCII byte at offset %d", i)
		}
	}
}

func TestManagedSettingsPathsMatchTheSCAPolicy(t *testing.T) {
	fileRule := regexp.MustCompile(`'f:([^']+?managed-settings\.json)`)
	sh, ps := read(t, shScript), read(t, psScript)

	for _, m := range fileRule.FindAllStringSubmatch(read(t, scaUnix), -1) {
		if !strings.Contains(sh, m[1]) {
			t.Errorf("install-system.sh does not install managed settings at %s, where the SCA policy reads them", m[1])
		}
	}
	win := fileRule.FindAllStringSubmatch(read(t, scaWin), -1)
	if len(win) == 0 {
		t.Fatal("no managed-settings path in the Windows SCA policy; this test has nothing to pin")
	}
	for _, m := range win {

		suffix := m[1][strings.Index(m[1], `ClaudeCode\`):]
		if !strings.Contains(ps, suffix) || !strings.Contains(m[1], `C:\Program Files\`) {
			t.Errorf("install-system.ps1 does not install managed settings at %s", m[1])
		}
	}
}

func TestBundleHookURLMatchesTheDefaultHookAddress(t *testing.T) {
	want := "http://" + config.Default().HookAddr + "/hook"
	if !strings.Contains(read(t, bundle), want) {
		t.Errorf("the M0 bundle does not point its hooks at %s", want)
	}
}
