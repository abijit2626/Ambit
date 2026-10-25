package stopctl

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func post(t *testing.T, h http.Handler, tok, origin string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, Path, nil)
	if tok != "" {
		req.Header.Set(Header, tok)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestHandlerStopsOnlyForTheToken(t *testing.T) {
	var stops atomic.Int32
	h := Handler("right", func() { stops.Add(1) })

	if got := post(t, h, "", ""); got != http.StatusForbidden {
		t.Errorf("no token: %d, want 403", got)
	}
	if got := post(t, h, "wrong", ""); got != http.StatusForbidden {
		t.Errorf("wrong token: %d, want 403", got)
	}
	if got := post(t, h, "right", "http://evil.test"); got != http.StatusForbidden {
		t.Errorf("right token from a browser: %d, want 403", got)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", rec.Code)
	}
	if stops.Load() != 0 {
		t.Fatalf("stopped %d times before the right request", stops.Load())
	}
	if got := post(t, h, "right", ""); got != http.StatusAccepted {
		t.Errorf("right token: %d, want 202", got)
	}
	post(t, h, "right", "")
	if stops.Load() != 1 {
		t.Errorf("stop ran %d times, want once", stops.Load())
	}
}

func TestAnEmptyTokenOpensNothing(t *testing.T) {
	var stopped bool
	h := Handler("", func() { stopped = true })
	if got := post(t, h, "", ""); got != http.StatusForbidden || stopped {
		t.Errorf("empty token: %d, stopped %v; want 403 and no stop", got, stopped)
	}
}

func TestWriteTokenReplacesTheLastRunsToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data", FileName)
	a, err := WriteToken(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := WriteToken(p)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(b) != 64 {
		t.Errorf("tokens %q then %q: want two different 64-hex tokens", a, b)
	}
	got, err := readToken(p)
	if err != nil || got != b {
		t.Errorf("read %q, %v; want the latest token", got, err)
	}
	if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("token file mode %v: readable beyond its owner", fi.Mode().Perm())
	}
}

// fakeAmbitd answers /healthz until /shutdown receives the token, then closes, as ambitd does.
func fakeAmbitd(t *testing.T, dir string) (cfgPath string, stopped *atomic.Bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	traj := filepath.Join(dir, "trajectory.jsonl")
	tok, err := WriteToken(TokenPath(traj))
	if err != nil {
		t.Fatal(err)
	}
	stopped = &atomic.Bool{}
	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle(Path, Handler(tok, func() {
		stopped.Store(true)
		go srv.Close()
	}))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })

	cfg := map[string]any{"hook_addr": ln.Addr().String(), "trajectory_path": traj,
		"events_path": filepath.Join(dir, "events.jsonl"), "fingerprint_key_path": filepath.Join(dir, "fp.key")}
	raw, _ := json.Marshal(cfg)
	cfgPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, stopped
}

func TestMainStopsARunningAmbitd(t *testing.T) {
	cfg, stopped := fakeAmbitd(t, t.TempDir())
	var out, errb bytes.Buffer
	if code := Main([]string{"-config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !stopped.Load() || !strings.Contains(out.String(), "ambitd stopped") {
		t.Errorf("stopped %v, output %q", stopped.Load(), out.String())
	}
}

func TestMainWithAStaleTokenFails(t *testing.T) {
	dir := t.TempDir()
	cfg, stopped := fakeAmbitd(t, dir)
	if err := os.WriteFile(TokenPath(filepath.Join(dir, "trajectory.jsonl")), []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"-config", cfg}, &out, &errb); code != 1 || stopped.Load() {
		t.Errorf("exit %d, stopped %v: want 1 and still running (%s)", code, stopped.Load(), errb.String())
	}
}

func TestMainWhenNothingRunsSucceeds(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"hook_addr":"127.0.0.1:1","trajectory_path":"`+filepath.ToSlash(filepath.Join(dir, "t.jsonl"))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"-config", cfg}, &out, &errb); code != 0 || !strings.Contains(out.String(), "not running") {
		t.Errorf("exit %d, output %q %q", code, out.String(), errb.String())
	}
}
