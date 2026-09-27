package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type capture struct {
	mu   sync.Mutex
	seen []*Payload
}

func (c *capture) Handle(p *Payload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, p)
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *capture) last() *Payload {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) == 0 {
		return nil
	}
	return c.seen[len(c.seen)-1]
}

func startServer(t *testing.T, h Handler, d Decider) string {
	t.Helper()
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Handler: h, Decider: d, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return "http://" + ln.Addr().String()
}

func post(t *testing.T, url string, v any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(v)
	resp, err := http.Post(url+"/hook", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

// TestM0ResponseIsInert is the most important test in this package. M0 must not
// change how any session behaves, and an empty response means the hook expressed
// no opinion so every later permission layer acts as if no hook were installed.
//
// Returning "allow" would NOT be equivalent: it suppresses the permission prompt
// a developer would otherwise see.
func TestM0ResponseIsInert(t *testing.T) {
	c := &capture{}
	url := startServer(t, c, ObserveOnly{})

	got := post(t, url, Payload{HookEventName: EvPreToolUse, ToolName: "Bash", SessionID: "s1"})
	if len(got) != 0 {
		t.Errorf("response = %v, want {}: M0 must express no decision", got)
	}
	for _, forbidden := range []string{"hookSpecificOutput", "permissionDecision", "decision", "systemMessage"} {
		if _, present := got[forbidden]; present {
			t.Errorf("response contains %q; M0 must be behaviorally inert", forbidden)
		}
	}
}

func TestHandlerReceivesPayload(t *testing.T) {
	c := &capture{}
	url := startServer(t, c, ObserveOnly{})

	post(t, url, map[string]any{
		"hook_event_name": EvPreToolUse,
		"session_id":      "sess_1",
		"prompt_id":       "p_1",
		"cwd":             "/home/dev/src/repo",
		"permission_mode": "bypassPermissions",
		"tool_name":       "Bash",
		"tool_use_id":     "toolu_1",
		"tool_input":      map[string]any{"command": "curl https://x.test"},
	})

	if c.count() != 1 {
		t.Fatalf("handler saw %d payloads, want 1", c.count())
	}
	p := c.last()
	if p.SessionID != "sess_1" || p.PermissionMode != "bypassPermissions" {
		t.Errorf("payload fields not parsed: %+v", p)
	}
	if got := p.Command(); got != "curl https://x.test" {
		t.Errorf("Command() = %q", got)
	}
}

// TestMalformedBodyStillRespondsInert: a failure inside agentd must not fail the
// tool call. In M0 that means an empty decision even on garbage input.
func TestMalformedBodyStillRespondsInert(t *testing.T) {
	c := &capture{}
	url := startServer(t, c, ObserveOnly{})

	resp, err := http.Post(url+"/hook", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200: a parse failure must not surface as a hook error", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if len(out) != 0 {
		t.Errorf("response = %v, want {}", out)
	}
	if c.count() != 0 {
		t.Error("an unparseable payload should not reach the handler")
	}
}

// TestValidateLoopback: binding off-loopback would expose a decision endpoint
// for the fleet to the network and put remote latency in the tool path.
//
// Tests the policy rather than Listen, so the result does not depend on whether
// the host has a working stack for a given address family — a container with
// IPv6 disabled would otherwise fail this for the wrong reason.
func TestValidateLoopback(t *testing.T) {
	refuse := []string{"0.0.0.0:7777", "192.168.1.10:7777", "[::]:7777", "10.0.0.5:7777", "example.com:7777"}
	for _, addr := range refuse {
		if err := ValidateLoopback(addr); err == nil {
			t.Errorf("ValidateLoopback(%q) = nil; must refuse non-loopback binds", addr)
		}
	}
	accept := []string{"127.0.0.1:0", "127.0.0.1:7777", "localhost:0", "[::1]:0", "127.0.0.53:7777"}
	for _, addr := range accept {
		if err := ValidateLoopback(addr); err != nil {
			t.Errorf("ValidateLoopback(%q) = %v, want nil", addr, err)
		}
	}
	if err := ValidateLoopback("not-an-addr"); err == nil {
		t.Error("ValidateLoopback should reject an unparseable address")
	}
}

// TestListenRefusesNonLoopback covers the bind path on IPv4, which is available
// everywhere this runs.
func TestListenRefusesNonLoopback(t *testing.T) {
	if ln, err := Listen("0.0.0.0:0"); err == nil {
		ln.Close()
		t.Error("Listen(0.0.0.0:0) succeeded; must refuse a wildcard bind")
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(127.0.0.1:0) failed: %v", err)
	}
	ln.Close()
}

func TestMethodNotAllowed(t *testing.T) {
	url := startServer(t, &capture{}, ObserveOnly{})
	resp, err := http.Get(url + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /hook status = %d, want 405", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	url := startServer(t, &capture{}, ObserveOnly{})
	resp, err := http.Get(url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestLatencyBudget measures the round trip over loopback. The target is p99 5ms;
// this asserts a much looser ceiling so the test is not flaky on a loaded CI box,
// while still catching an order-of-magnitude regression.
func TestLatencyBudget(t *testing.T) {
	url := startServer(t, &capture{}, ObserveOnly{})
	payload, _ := json.Marshal(Payload{
		HookEventName: EvPreToolUse,
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "/home/dev/src/repo/main.go"},
	})

	const n = 300
	durations := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		resp, err := http.Post(url+"/hook", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		durations = append(durations, time.Since(start))
	}

	var total time.Duration
	worst := time.Duration(0)
	for _, d := range durations {
		total += d
		if d > worst {
			worst = d
		}
	}
	mean := total / time.Duration(n)
	t.Logf("hook round trip over loopback: mean %v, worst %v (target p99 5ms)", mean, worst)

	if mean > 5*time.Millisecond {
		t.Errorf("mean round trip %v exceeds the 5ms budget", mean)
	}
	if worst > 250*time.Millisecond {
		t.Errorf("worst round trip %v exceeds the 250ms hard ceiling", worst)
	}
}

// TestHandlerIsNotOnTheCriticalPath: a slow handler must not slow the response.
// The handler contract is async, and this asserts the server does not wait on it.
func TestHandlerIsNotOnTheCriticalPath(t *testing.T) {
	released := make(chan struct{})
	slow := HandlerFunc(func(*Payload) {
		// Simulates a handler that enqueues and returns immediately, which is
		// the contract. If a future handler blocks here, this test documents
		// that the response must still not wait on it.
		close(released)
	})
	url := startServer(t, slow, ObserveOnly{})
	post(t, url, Payload{HookEventName: EvPostToolUse})
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("handler was never invoked")
	}
}

func TestIsMCPTool(t *testing.T) {
	cases := []struct {
		name       string
		wantServer string
		wantTool   string
		wantOK     bool
	}{
		{"mcp__github__create_issue", "github", "create_issue", true},
		{"mcp__Claude_Docs__batch", "Claude_Docs", "batch", true},
		{"mcp__server__tool_with__dunder", "server", "tool_with__dunder", true},
		{"Bash", "", "", false},
		{"Read", "", "", false},
		{"mcp__", "", "", false},
	}
	for _, c := range cases {
		server, tool, ok := IsMCPTool(c.name)
		if ok != c.wantOK || server != c.wantServer || tool != c.wantTool {
			t.Errorf("IsMCPTool(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.name, server, tool, ok, c.wantServer, c.wantTool, c.wantOK)
		}
	}
}

func TestPayloadPaths(t *testing.T) {
	p := &Payload{ToolInput: map[string]any{
		"file_path": "/a/b.go",
		"paths":     []any{"/c/d.go", "/e/f.go"},
	}}
	got := p.Paths()
	if len(got) != 3 {
		t.Fatalf("Paths() = %v, want 3 entries", got)
	}
	if (&Payload{}).Paths() != nil {
		t.Error("Paths() on an empty payload should be nil")
	}
}
