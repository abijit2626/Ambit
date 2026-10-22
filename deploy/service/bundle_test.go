package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
)

const (
	bundleWindows = "../claude-code/managed-settings.m0.windows.json"

	// earlierBundle is managed-settings.m0.json as every installer shipped it before SessionStart
	// became a command hook. Its SHA-256 is what the installers recognise as safe to upgrade.
	earlierBundle = "testdata/managed-settings.m0.shipped-before-hook-forward.json"

	windowsForwarder = `"C:/Program Files/ambit/ambitd.exe" hook-forward`
)

type hookEntry struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Command string `json:"command"`
}

type hookGroup struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

func loadHooks(t *testing.T, path string) map[string][]hookGroup {
	t.Helper()
	var doc struct {
		Hooks map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(read(t, path)), &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	out := map[string][]hookGroup{}
	for event, raw := range doc.Hooks {
		if strings.HasPrefix(event, "_") {
			continue
		}
		var groups []hookGroup
		if err := json.Unmarshal(raw, &groups); err != nil {
			t.Fatalf("%s: hooks.%s: %v", path, event, err)
		}
		out[event] = groups
	}
	return out
}

func forwarderCommand(t *testing.T, path string) string {
	t.Helper()
	groups := loadHooks(t, path)["SessionStart"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 {
		t.Fatalf("%s: SessionStart has %d groups, want one group with one hook", path, len(groups))
	}
	return groups[0].Hooks[0].Command
}

// Claude Code v2.1.278 fires SessionStart but does not deliver it to an http hook (observed on
// Windows: the same event reached a command hook and never an http one). A bundle that went back
// to http for it would look fine and silently lose every session_start.
func TestSessionStartIsTheOnlyCommandHookInEveryBundle(t *testing.T) {
	wantURL := "http://" + config.Default().HookAddr + "/hook"
	for _, path := range []string{bundle, bundleWindows} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			hooks := loadHooks(t, path)
			for event, groups := range hooks {
				for _, g := range groups {
					for _, h := range g.Hooks {
						switch {
						case event == "SessionStart" && h.Type != "command":
							t.Errorf("SessionStart is a %q hook; Claude Code does not deliver that event to an http hook", h.Type)
						case event == "SessionStart" && h.URL != "":
							t.Errorf("SessionStart still carries url %q", h.URL)
						case event != "SessionStart" && (h.Type != "http" || h.URL != wantURL || h.Command != ""):
							t.Errorf("%s hook is %+v, want an http hook to %s: only SessionStart needs a command", event, h, wantURL)
						}
					}
				}
			}
			if _, ok := hooks["SessionStart"]; !ok {
				t.Fatal("no SessionStart hook")
			}
			if !strings.HasSuffix(forwarderCommand(t, path), " hook-forward") {
				t.Errorf("SessionStart command %q does not end in the hook-forward subcommand", forwarderCommand(t, path))
			}
		})
	}
}

func TestBundlesDifferOnlyInTheForwarderCommand(t *testing.T) {
	unix, win := read(t, bundle), read(t, bundleWindows)
	jsonQuoted := strings.ReplaceAll(windowsForwarder, `"`, `\"`)
	got := strings.Replace(win, `"command": "`+jsonQuoted+`"`, `"command": "`+binPath+` hook-forward"`, 1)
	if got != unix {
		t.Errorf("the Windows bundle differs from the Unix one in more than the SessionStart command; they must stay in step, because the SCA policies and the drift runbook treat them as one bundle")
	}
}

func TestForwarderCommandNamesWhereTheInstallerPutsTheBinary(t *testing.T) {
	if got, want := forwarderCommand(t, bundle), binPath+" hook-forward"; got != want {
		t.Errorf("Unix bundle runs %q, want %q", got, want)
	}
	if !regexp.MustCompile(`(?m)^BIN_PATH=` + regexp.QuoteMeta(binPath) + `$`).MatchString(read(t, shScript)) {
		t.Errorf("install-system.sh no longer installs to %s, which the bundle names", binPath)
	}

	if got := forwarderCommand(t, bundleWindows); got != windowsForwarder {
		t.Errorf("Windows bundle runs %q, want %q", got, windowsForwarder)
	}
	ps := read(t, psScript)
	for _, want := range []string{`$BinDir   = Join-Path $ProgramFiles 'ambit'`, `$BinPath  = Join-Path $BinDir 'ambitd.exe'`} {
		if !strings.Contains(ps, want) {
			t.Errorf("install-system.ps1 no longer has %q, so the Windows bundle's path may not be where the binary goes", want)
		}
	}
}

func TestInstallersTellTheOperatorToExpectSessionStart(t *testing.T) {
	for _, path := range []string{psScript, shScript} {
		text := read(t, path)
		if !strings.Contains(text, "session_start line and a prompt_submit line") {
			t.Errorf("%s does not tell the operator to expect both a session_start and a prompt_submit line", path)
		}
		if strings.Contains(text, "is not expected") {
			t.Errorf("%s still says a session_start line is not expected, which was true only while SessionStart went over http", path)
		}
	}
}

func TestEarlierBundleHashIsPinnedInBothInstallers(t *testing.T) {
	sum := sha256.Sum256([]byte(read(t, earlierBundle)))
	want := hex.EncodeToString(sum[:])

	if !strings.Contains(strings.ToLower(read(t, shScript)), `earlier_bundles="`+want+`"`) {
		t.Errorf("install-system.sh does not list %s as the earlier bundle", want)
	}
	if !strings.Contains(strings.ToLower(read(t, psScript)), `$earlierbundles = @('`+want+`')`) {
		t.Errorf("install-system.ps1 does not list %s as the earlier bundle", want)
	}
	for _, path := range []string{bundle, bundleWindows} {
		cur := sha256.Sum256([]byte(read(t, path)))
		if hex.EncodeToString(cur[:]) == want {
			t.Errorf("%s is byte for byte the earlier bundle, so it was not changed", path)
		}
	}
	if !strings.Contains(read(t, earlierBundle), `"type": "http", "url": "http://127.0.0.1:7777/hook" } ] }
    ],
    "SessionEnd"`) {
		t.Error("the pinned earlier bundle does not register SessionStart over http; it is not the file it claims to be")
	}
}

// shellLibrary is install-system.sh without its OS gate, argument handling and dispatch, so the
// functions can be called one at a time against a temp directory. The gate is cut out because the
// script refuses any OS but Linux and macOS (Git Bash on a Windows runner answers MINGW64_NT-...,
// and Git Bash resolves its own uname before one placed on the PATH), while the functions tested
// here (the hash check, the bundle check, the install and remove steps) do not depend on the OS.
func shellLibrary(t *testing.T) string {
	t.Helper()
	text := read(t, shScript)
	cut := strings.Index(text, "\nmode=install bin=")
	if cut < 0 {
		t.Fatal("install-system.sh no longer has the argument-handling section this test cuts at")
	}
	gate := strings.Index(text, "\ncase \"$(uname -s)\" in")
	gateEnd := strings.Index(text[gate+1:], "\nesac\n")
	if gate < 0 || gateEnd < 0 || gate+1+gateEnd > cut {
		t.Fatal("install-system.sh no longer opens with the case on uname -s that this test cuts out")
	}
	lib := text[:gate] + "\nOS=linux\n" + text[gate+1+gateEnd+len("\nesac"):cut]
	if strings.Contains(lib, "uname") {
		t.Fatal("the library still calls uname outside the cut-out case")
	}
	path := filepath.Join(t.TempDir(), "lib.sh")
	if err := os.WriteFile(path, []byte(lib), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// shellEnv is the environment for a bash that sources the library built by shellLibrary. Paths are
// passed with forward slashes, which both Git Bash and a Unix shell read.
func shellEnv(kv ...string) []string {
	env := os.Environ()
	for _, e := range kv {
		k, v, _ := strings.Cut(e, "=")
		env = append(env, k+"="+filepath.ToSlash(v))
	}
	return env
}

func TestShellInstallerUpgradesOnlyTheEarlierBundle(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		if _, err := exec.LookPath("shasum"); err != nil {
			t.Skip("no sha256 tool")
		}
	}
	lib := shellLibrary(t)
	newBundle, _ := filepath.Abs(bundle)
	older, _ := filepath.Abs(earlierBundle)

	cases := []struct {
		name, existing  string
		wantErr         bool
		wantOut         string
		wantBecomesNew  bool
		wantUntouchedAs string
	}{
		{name: "no managed settings yet", wantBecomesNew: true, wantOut: "installed managed settings"},
		{name: "already the current bundle", existing: "@" + newBundle, wantBecomesNew: true, wantOut: "already match"},
		{name: "the earlier bundle is upgraded", existing: "@" + older, wantBecomesNew: true, wantOut: "upgraded managed settings"},
		{name: "an organization's own policy is left alone", existing: `{"permissions":{"deny":["Bash(rm *)"]}}`, wantErr: true, wantOut: "differ from the M0 bundle", wantUntouchedAs: `{"permissions":{"deny":["Bash(rm *)"]}}`},
		{name: "the earlier bundle with one byte changed is not ours", existing: "@" + older + "+", wantErr: true, wantOut: "differ from the M0 bundle"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			managed := filepath.Join(dir, "cc", "managed-settings.json")
			var before []byte
			if c.existing != "" {
				if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
					t.Fatal(err)
				}
				switch {
				case strings.HasPrefix(c.existing, "@") && strings.HasSuffix(c.existing, "+"):
					before = append([]byte(read(t, strings.TrimSuffix(c.existing[1:], "+"))), ' ')
				case strings.HasPrefix(c.existing, "@"):
					before = []byte(read(t, c.existing[1:]))
				default:
					before = []byte(c.existing)
				}
				if err := os.WriteFile(managed, before, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			script := `. "$LIB"; BUNDLE="$NEWBUNDLE"; MANAGED="$MANAGED_PATH"; install_managed_settings`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = shellEnv("LIB="+lib, "NEWBUNDLE="+newBundle, "MANAGED_PATH="+managed)
			out, err := cmd.CombinedOutput()
			if c.wantErr != (err != nil) {
				t.Fatalf("error = %v, want error %v\n%s", err, c.wantErr, out)
			}
			if !strings.Contains(string(out), c.wantOut) {
				t.Errorf("output does not say %q:\n%s", c.wantOut, out)
			}
			got, _ := os.ReadFile(managed)
			if c.wantBecomesNew && string(got) != read(t, bundle) {
				t.Errorf("managed settings are not the current bundle afterwards")
			}
			if !c.wantBecomesNew && string(got) != string(before) {
				t.Errorf("managed settings were modified although the installer refused")
			}
			if leftover, _ := filepath.Glob(managed + ".new"); len(leftover) != 0 {
				t.Errorf("a staging file was left behind: %v", leftover)
			}
		})
	}

	t.Run("uninstall removes the earlier bundle but not a foreign file", func(t *testing.T) {
		dir := t.TempDir()
		for name, src := range map[string][]byte{"earlier.json": []byte(read(t, earlierBundle)), "foreign.json": []byte(`{"x":1}`)} {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, src, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `. "$LIB"; BUNDLE="$NEWBUNDLE"; MANAGED="$MANAGED_PATH"; remove_managed_settings`)
			cmd.Env = shellEnv("LIB="+lib, "NEWBUNDLE="+newBundle, "MANAGED_PATH="+p)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v\n%s", name, err, out)
			}
			_, statErr := os.Stat(p)
			if removed := os.IsNotExist(statErr); removed != (name == "earlier.json") {
				t.Errorf("%s: removed=%v", name, removed)
			}
		}
	})

	t.Run("the install refuses a bundle for another binary path", func(t *testing.T) {
		dir := t.TempDir()
		wrong := filepath.Join(dir, "b.json")
		if err := os.WriteFile(wrong, []byte(strings.ReplaceAll(read(t, bundle), binPath+" hook-forward", "/opt/ambitd hook-forward")), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, path := range map[string]string{"wrong": wrong, "right": newBundle} {
			cmd := exec.Command("bash", "-c", `. "$LIB"; BUNDLE="$B"; bundle_problem`)
			cmd.Env = shellEnv("LIB="+lib, "B="+path)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", name, err, out)
			}
			if problem := strings.TrimSpace(string(out)); (problem != "") != (name == "wrong") {
				t.Errorf("%s: bundle_problem said %q", name, problem)
			}
		}
	})
}

func TestPowerShellInstallerUpgradesOnlyTheEarlierBundle(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	script, _ := filepath.Abs(psScript)
	newBundle, _ := filepath.Abs(bundleWindows)
	older, _ := filepath.Abs(earlierBundle)

	run := func(t *testing.T, dir, managed, body string) (string, error) {
		t.Helper()
		env := append(os.Environ(), "ProgramW6432="+dir, "ProgramFiles="+dir, "ProgramData="+dir, "SystemRoot="+dir)
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command",
			". '"+script+"'; $Managed = '"+managed+"'; "+body)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	cases := []struct {
		name, existing string
		wantOut        string
		wantNew        bool
	}{
		{"no managed settings yet", "", "installed managed settings", true},
		{"already the current bundle", newBundle, "already match", true},
		{"the earlier bundle is upgraded", older, "upgraded managed settings", true},
		{"an organization's own policy is left alone", "foreign", "differ from the M0 bundle", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			managed := filepath.Join(dir, "cc", "managed-settings.json")
			var before string
			if c.existing != "" {
				if err := os.MkdirAll(filepath.Dir(managed), 0o755); err != nil {
					t.Fatal(err)
				}
				before = `{"permissions":{"deny":["Bash(rm *)"]}}`
				if c.existing != "foreign" {
					before = read(t, c.existing)
				}
				if err := os.WriteFile(managed, []byte(before), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, runErr := run(t, dir, managed, "$Bundle = '"+newBundle+"'; try { Install-ManagedSettings } catch { $_.Exception.Message }")
			if runErr != nil {
				t.Fatalf("pwsh failed: %v\n%s", runErr, out)
			}
			if !strings.Contains(out, c.wantOut) {
				t.Errorf("output does not say %q:\n%s", c.wantOut, out)
			}
			got, _ := os.ReadFile(managed)
			if c.wantNew && string(got) != read(t, bundleWindows) {
				t.Errorf("managed settings are not the current Windows bundle afterwards")
			}
			if !c.wantNew && string(got) != before {
				t.Errorf("managed settings were modified although the installer refused")
			}
			if _, err := os.Stat(managed + ".new"); err == nil {
				t.Errorf("a staging file was left behind")
			}
		})
	}

	t.Run("uninstall removes the earlier bundle but not a foreign file", func(t *testing.T) {
		for name, src := range map[string]string{"earlier.json": read(t, earlierBundle), "foreign.json": `{"x":1}`} {
			dir := t.TempDir()
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			out, runErr := run(t, dir, p, "$Bundle = '"+newBundle+"'; Remove-ManagedSettings")
			if runErr != nil {
				t.Fatalf("%s: %v\n%s", name, runErr, out)
			}
			_, statErr := os.Stat(p)
			if removed := os.IsNotExist(statErr); removed != (name == "earlier.json") {
				t.Errorf("%s: removed=%v\n%s", name, removed, out)
			}
		}
	})

	t.Run("the install refuses a bundle for another binary path", func(t *testing.T) {
		dir := t.TempDir()
		wrong := filepath.Join(dir, "b.json")
		if err := os.WriteFile(wrong, []byte(strings.ReplaceAll(read(t, bundleWindows), "C:/Program Files/ambit/", "D:/Tools/ambit/")), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, path := range map[string]string{"wrong": wrong, "right": newBundle} {
			out, runErr := run(t, dir, filepath.Join(dir, "m.json"),
				"$BinPath = 'C:\\Program Files\\ambit\\ambitd.exe'; $Bundle = '"+path+"'; Get-BundleProblem")
			if runErr != nil {
				t.Fatalf("%s: %v\n%s", name, runErr, out)
			}
			if problem := strings.TrimSpace(out); (problem != "") != (name == "wrong") {
				t.Errorf("%s: Get-BundleProblem said %q", name, problem)
			}
		}
	})
}
