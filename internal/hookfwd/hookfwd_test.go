package hookfwd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// realSessionStart has the keys of a SessionStart payload captured on Claude Code v2.1.278 on
// Windows (values replaced). It carries no permission_mode.
const realSessionStart = `{"cwd":"D:/work/proj","hook_event_name":"SessionStart","model":"m","scratchpad_dir":"D:/s","session_id":"00000000-0000-0000-0000-000000000000","source":"startup","transcript_path":"D:/t.jsonl"}`

type seen struct {
	mu     sync.Mutex
	method string
	path   string
	ctype  string
	body   []byte
	calls  int
}

func (s *seen) handler(status int, delay time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.method, s.path, s.ctype, s.body = r.Method, r.URL.Path, r.Header.Get("Content-Type"), b
		s.calls++
		s.mu.Unlock()
		time.Sleep(delay)
		w.WriteHeader(status)
		_, _ = w.Write([]byte("{}"))
	})
}

func hostOf(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

func TestForwardsThePayloadUnchanged(t *testing.T) {
	var got seen
	srv := httptest.NewServer(got.handler(200, 0))
	defer srv.Close()

	var stderr bytes.Buffer
	code := Main([]string{"-addr", hostOf(srv)}, strings.NewReader(realSessionStart), &stderr)

	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("a successful forward wrote to stderr: %q", stderr.String())
	}
	if got.calls != 1 || got.method != http.MethodPost || got.path != "/hook" {
		t.Errorf("request was %d x %s %s, want 1 x POST /hook", got.calls, got.method, got.path)
	}
	if got.ctype != "application/json" {
		t.Errorf("content type %q", got.ctype)
	}
	if string(got.body) != realSessionStart {
		t.Errorf("body changed in transit:\n got %s\nwant %s", got.body, realSessionStart)
	}
}

func TestFailsOpenAndSaysSoOnStderr(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	addr := hostOf(down)
	down.Close()

	cases := []struct {
		name  string
		args  []string
		stdin io.Reader
		want  string
	}{
		{"ambitd is not listening", []string{"-addr", addr}, strings.NewReader(realSessionStart), "did not take the payload"},
		{"unknown flag", []string{"-nope"}, strings.NewReader(realSessionStart), "bad arguments"},
		{"empty stdin", []string{"-addr", addr}, strings.NewReader(""), "no payload"},
		{"non-loopback address", []string{"-addr", "192.0.2.1:7777"}, strings.NewReader(realSessionStart), "refusing to send anything"},
		{"oversize payload", []string{"-addr", addr}, strings.NewReader(strings.Repeat("x", MaxBody+1)), "larger than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stderr bytes.Buffer
			start := time.Now()
			code := Main(c.args, c.stdin, &stderr)
			if code != 0 {
				t.Errorf("exit code %d, want 0: a monitoring failure must not fail the hook", code)
			}
			if !strings.Contains(stderr.String(), c.want) {
				t.Errorf("stderr %q does not say %q", stderr.String(), c.want)
			}
			if n := strings.Count(strings.TrimRight(stderr.String(), "\n"), "\n"); n != 0 {
				t.Errorf("stderr has %d lines, want one: %q", n+1, stderr.String())
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("took %s", d)
			}
		})
	}
}

func TestNeverSendsToANonLoopbackAddress(t *testing.T) {
	var got seen
	srv := httptest.NewServer(got.handler(200, 0))
	defer srv.Close()

	// The test server is on loopback, so this checks the validation order: the address is
	// rejected before stdin is read or anything is sent.
	for _, bad := range []string{"10.0.0.5:7777", "example.com:7777", "0.0.0.0:7777", "[::]:7777"} {
		var stderr bytes.Buffer
		Main([]string{"-addr", bad}, strings.NewReader(realSessionStart), &stderr)
		if !strings.Contains(stderr.String(), "refusing") {
			t.Errorf("%s: stderr %q", bad, stderr.String())
		}
	}
	if got.calls != 0 {
		t.Errorf("%d requests reached the server", got.calls)
	}
}

func TestGivesUpOnASlowAmbitd(t *testing.T) {
	var got seen
	srv := httptest.NewServer(got.handler(200, 600*time.Millisecond))
	defer srv.Close()

	var stderr bytes.Buffer
	start := time.Now()
	code := Main([]string{"-addr", hostOf(srv), "-timeout", "100ms"}, strings.NewReader(realSessionStart), &stderr)

	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	if d := time.Since(start); d > 450*time.Millisecond {
		t.Errorf("waited %s for a 100ms timeout", d)
	}
	if stderr.Len() == 0 {
		t.Error("a timed-out forward was silent")
	}
}

func TestReportsAnErrorStatusFromAmbitd(t *testing.T) {
	var got seen
	srv := httptest.NewServer(got.handler(500, 0))
	defer srv.Close()

	var stderr bytes.Buffer
	if code := Main([]string{"-addr", hostOf(srv)}, strings.NewReader(realSessionStart), &stderr); code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "500") {
		t.Errorf("stderr %q does not mention the status", stderr.String())
	}
}

func TestDoesNotWaitForeverForStdin(t *testing.T) {
	old := readTimeout
	readTimeout = 100 * time.Millisecond
	defer func() { readTimeout = old }()

	pr, pw := io.Pipe()
	defer pw.Close()

	var stderr bytes.Buffer
	start := time.Now()
	code := Main([]string{"-addr", "127.0.0.1:1"}, pr, &stderr)

	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("waited %s on a stdin that was never closed", d)
	}
	if !strings.Contains(stderr.String(), "not closed") {
		t.Errorf("stderr %q", stderr.String())
	}
}

func TestTakesTheAddressFromAConfigFile(t *testing.T) {
	var got seen
	srv := httptest.NewServer(got.handler(200, 0))
	defer srv.Close()

	cfg := t.TempDir() + "/config.json"
	if err := os.WriteFile(cfg, []byte(`{"hook_addr":"`+hostOf(srv)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := Main([]string{"-config", cfg}, strings.NewReader(realSessionStart), &stderr); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if got.calls != 1 {
		t.Errorf("%d requests reached the address from the config (stderr %q)", got.calls, stderr.String())
	}
}
