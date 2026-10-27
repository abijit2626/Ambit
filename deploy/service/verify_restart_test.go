package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	restartScript = "../../scripts/verify-restart.sh"
	restartPS     = "../../scripts/verify-restart.ps1"
)

func TestRestartScriptParses(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if out, err := exec.Command(bash, "-n", restartScript).CombinedOutput(); err != nil {
		t.Errorf("bash -n: %v\n%s", err, out)
	}
}

func TestRestartScriptReadsTheSameConfigAsTheInstaller(t *testing.T) {
	restart, install := read(t, restartScript), read(t, shScript)
	for _, want := range []string{
		"BIN_PATH=" + binPath,
		"CONFIG=" + linuxConfig,
		"CONFIG=" + darwinConfig,
	} {
		if !strings.Contains(restart, want) {
			t.Errorf("verify-restart.sh does not contain %q", want)
		}
		if !strings.Contains(install, want) {
			t.Errorf("install-system.sh does not contain %q; this test compares the two", want)
		}
	}
}

// ambitdRunning ignores zombies: a killed process stays listed until its parent reaps it.
func ambitdRunning() bool {
	out, _ := exec.Command("pgrep", "-x", "ambitd").Output()
	for _, p := range strings.Fields(string(out)) {
		st, _ := exec.Command("ps", "-o", "stat=", "-p", p).Output()
		if s := strings.TrimSpace(string(st)); s != "" && !strings.HasPrefix(s, "Z") {
			return true
		}
	}
	return false
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// daemonFixture builds a real ambitd named ambitd (the scripts find it by process name) and a
// config that puts it on a free port. It kills any ambitd it started when the test ends.
func daemonFixture(t *testing.T) (bin, cfg, url string, waitHealthy func()) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "ambitd")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/ambitd").CombinedOutput(); err != nil {
		t.Fatalf("build ambitd: %v\n%s", err, out)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg = filepath.Join(dir, "config.json")
	body := fmt.Sprintf(`{"hook_addr":%q,"otlp_enabled":false,"events_path":%q,"trajectory_path":%q,"baseline_dir":%q,"fingerprint_key_path":%q}`,
		addr, filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "trajectory.jsonl"), filepath.Join(dir, "baseline"), filepath.Join(dir, "key"))
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	url = "http://" + addr
	waitHealthy = func() {
		t.Helper()
		for i := 0; i < 50; i++ {
			if exec.Command("curl", "-fsS", "--max-time", "1", url+"/healthz").Run() == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("ambitd never answered its health endpoint")
	}
	t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-x", "ambitd").Run() })
	return bin, cfg, url, waitHealthy
}

// The script finds ambitd by process name, so the test has to run a real one under that
// name, kept alive by a shell loop standing in for the service manager.
func TestRestartScriptPassesWhenTheDaemonComesBackAndFailsWhenItDoesNot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script is for Linux and macOS")
	}
	for _, tool := range []string{"bash", "pgrep", "curl", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	if ambitdRunning() {
		t.Skip("an ambitd is already running here; the script would kill it")
	}

	bin, cfg, url, waitHealthy := daemonFixture(t)

	// Supervised: killing the daemon must be survivable, and the script must say so.
	loop := exec.Command("bash", "-c", `while :; do "$0" -config "$1" >/dev/null 2>&1; sleep 0.5; done`, bin, cfg)
	loop.SysProcAttr = newSession()
	if err := loop.Start(); err != nil {
		t.Fatal(err)
	}
	waitHealthy()
	out, err := exec.Command("bash", restartScript, "--url", url, "--timeout", "20").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("supervised daemon: err=%v\n%s", err, out)
	}
	stopSession(loop)
	_ = exec.Command("pkill", "-KILL", "-x", "ambitd").Run()
	time.Sleep(300 * time.Millisecond)

	// Unsupervised: nothing brings it back, so the script must fail rather than pass.
	alone := exec.Command(bin, "-config", cfg)
	alone.SysProcAttr = newSession()
	if err := alone.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = alone.Wait() }()
	waitHealthy()
	out, err = exec.Command("bash", restartScript, "--url", url, "--timeout", "2").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "FAIL") {
		t.Fatalf("unsupervised daemon should fail the check: err=%v\n%s", err, out)
	}
}

func TestRestartScriptRefusesWhenNothingIsRunning(t *testing.T) {
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skip("pgrep not installed")
	}
	if ambitdRunning() {
		t.Skip("an ambitd is already running here")
	}
	out, err := exec.Command("bash", restartScript, "--url", "http://127.0.0.1:1", "--timeout", "1").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no ambitd process is running") {
		t.Errorf("err=%v\n%s", err, out)
	}
}

// The same two outcomes through verify-restart.ps1, run under PowerShell 7 on this OS. The task
// scheduler is not involved, so this checks the script's logic and not the Windows restart.
func TestPowerShellRestartScriptPassesWhenTheDaemonComesBackAndFailsWhenItDoesNot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the process helpers here are for Linux and macOS")
	}
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not installed")
	}
	for _, tool := range []string{"bash", "pgrep", "curl", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	if ambitdRunning() {
		t.Skip("an ambitd is already running here; the script would end it")
	}
	script, err := filepath.Abs(restartPS)
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(pwsh, append([]string{"-NoProfile", "-NonInteractive", "-File", script}, args...)...).CombinedOutput()
		return string(out), err
	}

	bin, cfg, url, waitHealthy := daemonFixture(t)

	loop := exec.Command("bash", "-c", `while :; do "$0" -config "$1" >/dev/null 2>&1; sleep 0.5; done`, bin, cfg)
	loop.SysProcAttr = newSession()
	if err := loop.Start(); err != nil {
		t.Fatal(err)
	}
	waitHealthy()
	out, err := run("-Url", url, "-Timeout", "20")
	if err != nil || !strings.Contains(out, "PASS") {
		t.Fatalf("supervised daemon: err=%v\n%s", err, out)
	}
	stopSession(loop)
	_ = exec.Command("pkill", "-KILL", "-x", "ambitd").Run()
	time.Sleep(300 * time.Millisecond)

	alone := exec.Command(bin, "-config", cfg)
	alone.SysProcAttr = newSession()
	if err := alone.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = alone.Wait() }()
	waitHealthy()
	out, err = run("-Url", url, "-Timeout", "2")
	if err == nil || !strings.Contains(out, "FAIL") {
		t.Fatalf("unsupervised daemon should fail the check: err=%v\n%s", err, out)
	}
	_ = exec.Command("pkill", "-KILL", "-x", "ambitd").Run()
	time.Sleep(300 * time.Millisecond)

	out, err = run("-Url", url, "-Timeout", "2")
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.Contains(out, "no ambitd process is running") {
		t.Errorf("nothing running: err=%v\n%s", err, out)
	}
	out, err = run("-Timeout", "abc")
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
		t.Errorf("bad -Timeout should exit 2: err=%v\n%s", err, out)
	}
}

func TestPowerShellRestartScriptIsASCIIAndTestsACrashNotAStop(t *testing.T) {
	text := read(t, restartPS)
	for i, b := range []byte(text) {
		if b > 0x7f {
			t.Fatalf("verify-restart.ps1 has a non-ASCII byte at offset %d", i)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") || strings.HasPrefix(code, "Run ") {
			continue
		}
		if strings.Contains(code, "Stop-ScheduledTask") && !strings.Contains(code, "does not use") {
			t.Errorf("verify-restart.ps1 calls Stop-ScheduledTask, which tests the task and not a crash: %s", code)
		}
	}
	if !strings.Contains(text, "Stop-Process -Id $old -Force") {
		t.Error("verify-restart.ps1 does not end ambitd with Stop-Process -Force")
	}
	for _, want := range []string{"ambit", "ambitd"} {
		if !strings.Contains(text, want) {
			t.Errorf("verify-restart.ps1 never mentions %q", want)
		}
	}
}
