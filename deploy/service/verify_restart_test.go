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

const restartScript = "../../scripts/verify-restart.sh"

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

	dir := t.TempDir()
	bin := filepath.Join(dir, "ambitd")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/ambitd").CombinedOutput(); err != nil {
		t.Fatalf("build ambitd: %v\n%s", err, out)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := filepath.Join(dir, "config.json")
	body := fmt.Sprintf(`{"hook_addr":%q,"otlp_enabled":false,"events_path":%q,"trajectory_path":%q,"baseline_dir":%q,"fingerprint_key_path":%q}`,
		addr, filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "trajectory.jsonl"), filepath.Join(dir, "baseline"), filepath.Join(dir, "key"))
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	url := "http://" + addr

	healthy := func() bool {
		return exec.Command("curl", "-fsS", "--max-time", "1", url+"/healthz").Run() == nil
	}
	waitHealthy := func() {
		t.Helper()
		for i := 0; i < 50; i++ {
			if healthy() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("ambitd never answered its health endpoint")
	}
	t.Cleanup(func() { _ = exec.Command("pkill", "-KILL", "-x", "ambitd").Run() })

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
