package wazuh

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const expectScript = "../../scripts/expect-alert.sh"

// wazuhAlertJSON has the shape of a line in Wazuh's alerts.json.
func wazuhAlertJSON(rule int, agentID, agent, desc string) string {
	return fmt.Sprintf(`{"timestamp":"2026-10-27T10:00:00.123+0000","rule":{"level":12,"description":%q,"id":"%d","firedtimes":1,"mail":true,"groups":["ambit"]},"agent":{"id":%q,"name":%q,"ip":"10.0.0.2"},"manager":{"name":"wazuh"},"id":"1700000000.1","full_log":"x"}`+"\n",
		desc, rule, agentID, agent)
}

// lockedBuf is written by the exec copier goroutine while the test reads it.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type watch struct {
	cmd *exec.Cmd
	out *lockedBuf
	err chan error
}

func skipUnlessBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the script is for a Linux manager")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func startWatch(t *testing.T, file string, args ...string) *watch {
	t.Helper()
	w := &watch{out: &lockedBuf{}, err: make(chan error, 1)}
	w.cmd = exec.Command("bash", append([]string{expectScript, "--file", file}, args...)...)
	w.cmd.Stdout, w.cmd.Stderr = w.out, w.out
	if err := w.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { w.err <- w.cmd.Wait() }()
	// The script notes where the file ends when it starts: wait until it says so.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(w.out.String(), "listening") {
		if time.Now().After(deadline) {
			t.Fatalf("the script never started listening:\n%s", w.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return w
}

func (w *watch) wait(t *testing.T) (string, int) {
	t.Helper()
	select {
	case err := <-w.err:
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return w.out.String(), code
	case <-time.After(20 * time.Second):
		_ = w.cmd.Process.Kill()
		t.Fatalf("the script did not finish:\n%s", w.out.String())
		return "", -1
	}
}

func alertsFile(t *testing.T, initial string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts.json")
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExpectAlertParses(t *testing.T) {
	skipUnlessBash(t)
	if out, err := exec.Command("bash", "-n", expectScript).CombinedOutput(); err != nil {
		t.Errorf("bash -n: %v\n%s", err, out)
	}
}

func TestExpectAlertPassesOnAnAlertWrittenAfterItStarted(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	w := startWatch(t, file, "--rule", "100314", "--agent", "volunteer-laptop", "--timeout", "15")
	appendTo(t, file, wazuhAlertJSON(100314, "001", "volunteer-laptop", "ambit D7: telemetry gap"))
	out, code := w.wait(t)
	if code != 0 || !strings.Contains(out, "PASS") || !strings.Contains(out, "ambit D7: telemetry gap") {
		t.Errorf("code=%d\n%s", code, out)
	}
}

func TestExpectAlertIgnoresAnAlertFromBeforeItStarted(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, wazuhAlertJSON(100314, "001", "volunteer-laptop", "an earlier test"))
	w := startWatch(t, file, "--rule", "100314", "--timeout", "2")
	appendTo(t, file, wazuhAlertJSON(100271, "001", "volunteer-laptop", "something else"))
	out, code := w.wait(t)
	if code != 1 || !strings.Contains(out, "FAIL") || !strings.Contains(out, "100271(x1)") {
		t.Errorf("code=%d\n%s", code, out)
	}
	if strings.Contains(out, "earlier test") {
		t.Errorf("an old alert was reported:\n%s", out)
	}
}

func TestExpectAlertCountsOnlyTheNamedAgent(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	w := startWatch(t, file, "--rule", "100270", "--agent", "laptop-a", "--timeout", "2")
	appendTo(t, file, wazuhAlertJSON(100270, "002", "laptop-b", "another endpoint"))
	if out, code := w.wait(t); code != 1 {
		t.Errorf("another agent's alert passed: code=%d\n%s", code, out)
	}

	file = alertsFile(t, "")
	w = startWatch(t, file, "--rule", "100270", "--agent", "laptop-a", "--timeout", "10")
	appendTo(t, file, wazuhAlertJSON(100270, "002", "laptop-b", "another endpoint")+wazuhAlertJSON(100270, "003", "laptop-a", "the right one"))
	if out, code := w.wait(t); code != 0 || !strings.Contains(out, "the right one") {
		t.Errorf("code=%d\n%s", code, out)
	}
}

func TestExpectAlertDoesNotMistakeAnAgentIDForARuleID(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	w := startWatch(t, file, "--rule", "504", "--timeout", "2")
	appendTo(t, file, wazuhAlertJSON(100200, "504", "agent-504", "a different rule from an agent whose id is 504"))
	if out, code := w.wait(t); code != 1 {
		t.Errorf("an agent id matched as a rule id: code=%d\n%s", code, out)
	}
}

func TestExpectAlertAcceptsAnyOfSeveralRules(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	w := startWatch(t, file, "--rule", "100270", "--rule", "100271", "--timeout", "10")
	appendTo(t, file, wazuhAlertJSON(100271, "001", "a", "persisted"))
	if out, code := w.wait(t); code != 0 {
		t.Errorf("code=%d\n%s", code, out)
	}
}

func TestExpectAlertWaitsForTheRestOfALineStillBeingWritten(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	w := startWatch(t, file, "--rule", "100314", "--timeout", "15")
	line := wazuhAlertJSON(100314, "001", "a", "split across two writes")
	half := len(line) / 2
	appendTo(t, file, line[:half])
	time.Sleep(1500 * time.Millisecond)
	appendTo(t, file, line[half:])
	if out, code := w.wait(t); code != 0 || !strings.Contains(out, "split across two writes") {
		t.Errorf("code=%d\n%s", code, out)
	}
}

func TestExpectAlertFollowsARotatedFile(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, strings.Repeat(wazuhAlertJSON(100100, "001", "a", "filler"), 20))
	w := startWatch(t, file, "--rule", "100314", "--timeout", "15")
	// Wazuh moves alerts.json aside and starts a smaller one.
	if err := os.WriteFile(file, []byte(wazuhAlertJSON(100314, "001", "a", "after rotation")), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := w.wait(t); code != 0 || !strings.Contains(out, "after rotation") {
		t.Errorf("code=%d\n%s", code, out)
	}
}

func TestExpectAlertSaysWhenTheManagerWroteNothing(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	w := startWatch(t, file, "--rule", "100314", "--timeout", "2")
	out, code := w.wait(t)
	if code != 1 || !strings.Contains(out, "wrote no alerts at all") {
		t.Errorf("code=%d\n%s", code, out)
	}
}

func TestExpectAlertUsageErrorsExitTwo(t *testing.T) {
	skipUnlessBash(t)
	file := alertsFile(t, "")
	for name, args := range map[string][]string{
		"no rule":           {"--timeout", "5"},
		"rule not a number": {"--rule", "10x"},
		"bad timeout":       {"--rule", "1", "--timeout", "abc"},
		"zero timeout":      {"--rule", "1", "--timeout", "0"},
		"agent with regex":  {"--rule", "1", "--agent", "a.*b|c"},
		"unknown flag":      {"--nope"},
	} {
		out, err := exec.Command("bash", append([]string{expectScript, "--file", file}, args...)...).CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 2 {
			t.Errorf("%s: err=%v\n%s", name, err, out)
		}
	}
}

func TestExpectAlertRefusesWithoutAnAlertsFile(t *testing.T) {
	skipUnlessBash(t)
	out, err := exec.Command("bash", expectScript, "--file", filepath.Join(t.TempDir(), "none.json"), "--rule", "1").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no alerts file") {
		t.Errorf("err=%v\n%s", err, out)
	}
}
