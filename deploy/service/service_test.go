// Package service holds no code: it exists so the service definitions in this directory
// and the install scripts that place them can be checked by `go test ./...`.
//
// The failure these tests guard against is silent. A unit that points at a path the
// installer does not write, a managed-settings path the SCA policy does not read, or a
// Windows task that the default time limit kills after three days all install cleanly
// and then leave an endpoint unobserved. None of them is caught by a service manager
// here, so each is pinned as text against the place it must agree with.
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

// unit parses a systemd unit into section -> key -> value. Comments and blank lines are
// skipped; a repeated key keeps its last value, which is all these tests need.
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

// systemd-analyze verify exits 0 even for an unknown key, and only says so on its
// output. So any output at all fails this test.
func TestSystemdUnitPassesSystemdAnalyze(t *testing.T) {
	sa, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not installed")
	}
	// The binary does not exist on a build machine, and verify reports that too. Point
	// ExecStart at one that does, so the only thing left to report is the unit itself.
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

// plist decodes the flat top-level dict of a launchd property list.
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

// The script installs what the definitions reference, where they reference it.
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

// The Windows task has no service manager to fall back on, so the settings that keep it
// alive are pinned: start at boot as SYSTEM, no execution time limit (the default kills
// a task after 72 hours), restart on failure.
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

// Windows PowerShell 5.1 reads a script without a byte-order mark as the system ANSI code
// page, so a non-ASCII character there becomes garbage or a parse error.
func TestPowerShellInstallerIsASCII(t *testing.T) {
	for i, b := range []byte(read(t, psScript)) {
		if b > 0x7f {
			t.Fatalf("install-system.ps1 has a non-ASCII byte at offset %d", i)
		}
	}
}

// Managed settings go where the SCA policy looks for them. A mismatch would install the
// bundle somewhere Claude Code reads and fail check 10001 on every endpoint, or the reverse.
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
		// The script builds the path from Program Files; compare the part after it.
		suffix := m[1][strings.Index(m[1], `ClaudeCode\`):]
		if !strings.Contains(ps, suffix) || !strings.Contains(m[1], `C:\Program Files\`) {
			t.Errorf("install-system.ps1 does not install managed settings at %s", m[1])
		}
	}
}

// The bundle points Claude Code's hooks at ambitd's default address. The service runs with
// the default unless a config moves it, so the two must agree out of the box.
func TestBundleHookURLMatchesTheDefaultHookAddress(t *testing.T) {
	want := "http://" + config.Default().HookAddr + "/hook"
	if !strings.Contains(read(t, bundle), want) {
		t.Errorf("the M0 bundle does not point its hooks at %s", want)
	}
}
