package interpose

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abijit2626/ambit/internal/mcp"
)

func triggers(c *captureSender) []string {
	var out []string
	for _, r := range c.all() {
		out = append(out, r.Trigger)
	}
	return out
}

func listing(c *captureSender) *Report {
	for _, r := range c.all() {
		if r.Trigger == TriggerToolsList || r.Trigger == TriggerListChanged {
			return r
		}
	}
	return nil
}

const toolsResult = `{"tools":[{"name":"search","description":"Search the wiki","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}},{"name":"publish","description":"Publish a page to the wiki","inputSchema":{"type":"object"}}]}`

func reply(id json.RawMessage, method string) string {
	switch method {
	case "initialize":
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"wiki","version":"3.2.0"}}}`, id)
	case "tools/list":
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, toolsResult)
	case "tools/call":
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done"}]}}`, id)
	}
	return ""
}

// streamableServer is a Streamable HTTP MCP server: JSON for initialize and tools/call, an
// SSE response carrying a progress notification before the answer for tools/list, and a GET
// stream that announces a list change.
type streamableServer struct {
	t *testing.T

	mu        sync.Mutex
	posts     []http.Header
	deleted   string
	getStream chan struct{}
	fail      map[string]int
}

func (s *streamableServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		s.mu.Lock()
		s.deleted = r.Header.Get(headerSession)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet:
		if r.Header.Get(headerSession) != "sess-1" {
			http.Error(w, "no session", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "id: g1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		w.(http.Flusher).Flush()
		s.mu.Lock()
		if s.getStream != nil {
			close(s.getStream)
			s.getStream = nil
		}
		s.mu.Unlock()
		<-r.Context().Done()
		return
	}

	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.posts = append(s.posts, r.Header.Clone())
	code := s.fail[m.Method]
	s.mu.Unlock()
	if code != 0 {
		http.Error(w, "nope", code)
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		s.t.Errorf("POST without text/event-stream in Accept: %q", r.Header.Get("Accept"))
	}
	if len(m.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch m.Method {
	case "initialize":
		w.Header().Set(headerSession, "sess-1")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Pretty-printed, to prove the bridge reframes it onto one line.
		var v any
		_ = json.Unmarshal([]byte(reply(m.ID, m.Method)), &v)
		out, _ := json.MarshalIndent(v, "", "  ")
		w.Write(out)
	case "tools/list":
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n")
		fmt.Fprintf(w, ": keepalive\n\ndata: %s\n\n", reply(m.ID, m.Method))
	default:
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, reply(m.ID, m.Method))
	}
}

type bridgeRun struct {
	sender *captureSender
	stdout []string
	err    error
}

func runBridge(t *testing.T, u string, transport Transport, header http.Header, session string, wait <-chan struct{}) bridgeRun {
	t.Helper()
	target, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	sender := &captureSender{}
	a := NewAnalyzer(Options{Server: "wiki", Sender: sender})

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &Bridge{
		URL: target, Transport: transport, Header: header,
		FromClient: inR, ToClient: outW, Analyzer: a, Grace: time.Second,
	}

	var lines []string
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- b.Run(ctx)
		outW.Close()
	}()

	go func() {
		// A client sends the next message only after it has the answer to the last, so the
		// script waits a beat between them; the bridge does not rely on that for ordering.
		for _, line := range strings.Split(strings.TrimSpace(session), "\n") {
			if _, err := io.WriteString(inW, line+"\n"); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		if wait != nil {
			select {
			case <-wait:
			case <-time.After(5 * time.Second):
			}
			time.Sleep(50 * time.Millisecond)
		}
		inW.Close()
	}()

	err = <-runErr
	inR.Close()
	<-readDone
	closeCtx, c2 := context.WithTimeout(context.Background(), 2*time.Second)
	a.Close(closeCtx)
	c2()
	return bridgeRun{sender: sender, stdout: lines, err: err}
}

const bridgeSession = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"2.1.290"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`

func TestBridgeStreamableHTTP(t *testing.T) {
	srv := &streamableServer{t: t, getStream: make(chan struct{})}
	stream := srv.getStream
	ts := httptest.NewServer(srv)
	defer ts.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer test-token")
	run := runBridge(t, ts.URL+"/mcp", TransportHTTP, header, bridgeSession, stream)
	if run.err != nil {
		t.Fatalf("Run: %v", run.err)
	}

	byID := map[string]string{}
	var notifications []string
	for _, line := range run.stdout {
		m, err := mcp.Parse([]byte(line))
		if err != nil {
			t.Fatalf("client got a line that is not one JSON-RPC message: %q (%v)", line, err)
		}
		if m.IsNotification() {
			notifications = append(notifications, m.Method)
			continue
		}
		byID[m.IDKey()] = line
	}
	for _, id := range []string{"1", "2", "3"} {
		if byID[id] == "" {
			t.Errorf("no answer for request %s; got %q", id, run.stdout)
		}
		if strings.Contains(byID[id], "mcp-interpose:") {
			t.Errorf("request %s got a bridge error: %s", id, byID[id])
		}
	}
	if !strings.Contains(strings.Join(notifications, ","), "notifications/progress") ||
		!strings.Contains(strings.Join(notifications, ","), "notifications/tools/list_changed") {
		t.Errorf("notifications reaching the client: %q", notifications)
	}

	srv.mu.Lock()
	posts, deleted := srv.posts, srv.deleted
	srv.mu.Unlock()
	if len(posts) != 4 {
		t.Fatalf("server saw %d POSTs, want 4", len(posts))
	}
	for i, h := range posts {
		if h.Get("Authorization") != "Bearer test-token" {
			t.Errorf("POST %d lost the configured header", i)
		}
		if i == 0 {
			if h.Get(headerSession) != "" || h.Get(headerProtocol) != "" {
				t.Errorf("initialize carried session headers: %v", h)
			}
			continue
		}
		if h.Get(headerSession) != "sess-1" {
			t.Errorf("POST %d: %s = %q, want sess-1", i, headerSession, h.Get(headerSession))
		}
		if h.Get(headerProtocol) != "2025-06-18" {
			t.Errorf("POST %d: %s = %q, want the negotiated version", i, headerProtocol, h.Get(headerProtocol))
		}
	}
	if deleted != "sess-1" {
		t.Errorf("session not ended with DELETE on client exit; got %q", deleted)
	}

	rep := listing(run.sender)
	if rep == nil {
		t.Fatalf("no listing report; triggers %v", triggers(run.sender))
	}
	if rep.ServerInfo.Name != "wiki" || rep.ClientName != "claude-code" || len(rep.Tools) != 2 {
		t.Errorf("listing report: %+v", rep)
	}
	all := run.sender.all()
	if last := all[len(all)-1]; last.Trigger != TriggerShutdown || last.CallsObserved != 1 {
		t.Errorf("shutdown report: trigger %q, calls observed %d, want 1", last.Trigger, last.CallsObserved)
	}
	if !strings.Contains(strings.Join(triggers(run.sender), ","), TriggerNotification) {
		t.Errorf("list_changed on the GET stream did not reach the analyzer; triggers %v", triggers(run.sender))
	}
}

func TestBridgeAnswersARequestTheServerRefused(t *testing.T) {
	srv := &streamableServer{t: t, fail: map[string]int{"tools/call": http.StatusInternalServerError}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	run := runBridge(t, ts.URL, TransportHTTP, nil, bridgeSession, nil)
	if run.err != nil {
		t.Fatalf("Run: %v", run.err)
	}
	var got string
	for _, line := range run.stdout {
		if strings.Contains(line, `"id":3`) {
			got = line
		}
	}
	if !strings.Contains(got, `"error"`) || !strings.Contains(got, "500") {
		t.Fatalf("a refused call must still be answered with an error; got %q", got)
	}
}

func TestBridgeEndsWhenTheSessionExpires(t *testing.T) {
	srv := &streamableServer{t: t, fail: map[string]int{"tools/list": http.StatusNotFound}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	run := runBridge(t, ts.URL, TransportHTTP, nil, bridgeSession, nil)
	if !errors.Is(run.err, ErrSessionExpired) {
		t.Fatalf("Run = %v, want ErrSessionExpired", run.err)
	}
}

func TestBridgeUnreachableServerAnswersEveryRequest(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	u := ts.URL
	ts.Close()

	run := runBridge(t, u, TransportHTTP, nil, bridgeSession, nil)
	if run.err != nil {
		t.Fatalf("Run: %v", run.err)
	}
	errs := 0
	for _, line := range run.stdout {
		if strings.Contains(line, "upstream unreachable") {
			errs++
		}
	}
	if errs != 3 {
		t.Fatalf("want an error answer for each of 3 requests and none for the notification; got %q", run.stdout)
	}
}

// legacyServer is the 2024-11-05 transport: a GET stream whose first event names the POST
// endpoint, with every answer delivered on that stream.
type legacyServer struct {
	endpoint string
	msgs     chan string
	posts    chan http.Header
}

func (s *legacyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/sse":
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", s.endpoint)
		w.(http.Flusher).Flush()
		for {
			select {
			case msg, ok := <-s.msgs:
				if !ok {
					return
				}
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == "/messages":
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		s.posts <- r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, "Accepted")
		if len(m.ID) > 0 {
			s.msgs <- reply(m.ID, m.Method)
		}
		if m.Method == "tools/call" {
			close(s.msgs)
		}
	default:
		http.NotFound(w, r)
	}
}

func TestBridgeLegacySSE(t *testing.T) {
	srv := &legacyServer{endpoint: "/messages?sessionId=abc", msgs: make(chan string, 8), posts: make(chan http.Header, 8)}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	header := http.Header{}
	header.Set("X-Api-Key", "k")
	run := runBridge(t, ts.URL+"/sse", TransportSSE, header, bridgeSession, nil)
	if run.err != nil {
		t.Fatalf("Run: %v", run.err)
	}
	if len(run.stdout) != 3 {
		t.Fatalf("client got %d lines, want 3 answers: %q", len(run.stdout), run.stdout)
	}
	close(srv.posts)
	n := 0
	for h := range srv.posts {
		n++
		if h.Get("X-Api-Key") != "k" {
			t.Errorf("POST lost the configured header")
		}
	}
	if n != 4 {
		t.Errorf("server saw %d POSTs, want 4", n)
	}
	if rep := listing(run.sender); rep == nil || len(rep.Tools) != 2 {
		t.Errorf("no listing report from the SSE stream: %v", triggers(run.sender))
	}
}

func TestBridgeLegacyRefusesAnEndpointOnAnotherOrigin(t *testing.T) {
	srv := &legacyServer{endpoint: "https://elsewhere.test/messages", msgs: make(chan string, 8), posts: make(chan http.Header, 8)}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	run := runBridge(t, ts.URL+"/sse", TransportSSE, nil, bridgeSession, nil)
	if run.err == nil || !strings.Contains(run.err.Error(), "origin") {
		t.Fatalf("Run = %v, want a refusal naming the origin", run.err)
	}
	if len(srv.posts) != 0 {
		t.Fatalf("a message was posted despite the refusal")
	}
}

// A server may end a request's stream after an event id and before the answer; the bridge
// resumes it with Last-Event-ID rather than failing the call.
func TestBridgeResumesAStreamClosedBeforeTheAnswer(t *testing.T) {
	var resumedWith string
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			resumedWith = r.Header.Get(headerLastID)
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "id: e2\ndata: %s\n\n", reply(json.RawMessage("3"), "tools/call"))
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		switch {
		case len(m.ID) == 0:
			w.WriteHeader(http.StatusAccepted)
		case m.Method == "tools/call":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "id: e1\nretry: 10\ndata:\n\n")
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, reply(m.ID, m.Method))
		}
	}))
	defer ts.Close()

	session := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search"}}`
	run := runBridge(t, ts.URL, TransportHTTP, nil, session, nil)
	if run.err != nil {
		t.Fatalf("Run: %v", run.err)
	}
	if len(run.stdout) != 2 || !strings.Contains(run.stdout[1], `"text":"done"`) {
		t.Fatalf("the resumed answer did not reach the client: %q", run.stdout)
	}
	mu.Lock()
	defer mu.Unlock()
	if resumedWith != "e1" {
		t.Errorf("resumed with Last-Event-ID %q, want e1", resumedWith)
	}
}

func TestOneLine(t *testing.T) {
	for in, want := range map[string]string{
		"{\n  \"a\": \"x\\ny\"\n}\n": `{"a":"x\ny"}`,
		"not\njson":                  "not json",
		"  \n":                       "",
	} {
		if got := string(oneLine([]byte(in))); got != want {
			t.Errorf("oneLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTransport(t *testing.T) {
	for in, want := range map[string]Transport{"http": TransportHTTP, "Streamable-HTTP": TransportHTTP, " sse ": TransportSSE} {
		if got, err := ParseTransport(in); err != nil || got != want {
			t.Errorf("ParseTransport(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseTransport("stdio"); err == nil {
		t.Error("stdio is not an HTTP transport")
	}
}
