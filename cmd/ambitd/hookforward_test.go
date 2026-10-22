package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for the ambitd executable: a subprocess started with
// os.Args[0] and "hook-forward" runs the real main().
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "hook-forward" {
		main()
	}
	os.Exit(m.Run())
}

const sessionStart = `{"cwd":"D:/work/proj","hook_event_name":"SessionStart","model":"m","scratchpad_dir":"D:/s","session_id":"00000000-0000-0000-0000-000000000000","source":"startup","transcript_path":"D:/t.jsonl"}`

func runForwarder(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"hook-forward"}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

func TestHookForwardPrintsNothingOnStdoutAndExitsZero(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = b
		mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	}))
	down := httptest.NewServer(http.NotFoundHandler())
	downAddr := strings.TrimPrefix(down.URL, "http://")
	down.Close()
	defer srv.Close()

	cases := []struct {
		name  string
		stdin string
		args  []string
		sent  bool
	}{
		{"ambitd answers", sessionStart, []string{"-addr", strings.TrimPrefix(srv.URL, "http://")}, true},
		{"ambitd is down", sessionStart, []string{"-addr", downAddr}, false},
		{"empty stdin", "", []string{"-addr", downAddr}, false},
		{"non-loopback address", sessionStart, []string{"-addr", "192.0.2.1:7777"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			got = nil
			mu.Unlock()
			start := time.Now()
			stdout, stderr, code := runForwarder(t, c.stdin, c.args...)
			if stdout != "" {
				t.Errorf("stdout is %q; a SessionStart hook's stdout becomes model context, so it must be empty", stdout)
			}
			if code != 0 {
				t.Errorf("exit code %d, want 0", code)
			}
			if c.sent && stderr != "" {
				t.Errorf("a successful forward wrote %q to stderr", stderr)
			}
			if !c.sent && stderr == "" {
				t.Error("a failure was silent")
			}
			mu.Lock()
			delivered := string(got) == c.stdin && c.stdin != ""
			mu.Unlock()
			if delivered != c.sent {
				t.Errorf("delivered=%v, want %v", delivered, c.sent)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %s", d)
			}
		})
	}
}
