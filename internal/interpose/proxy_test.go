package interpose

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeServer models a real MCP server: it answers a request only after receiving
// it. That causality is the point of the test — a pre-canned response stream would
// let the response reach the analyzer before the request, which is exactly the bug
// mcp.ObserveFirst exists to prevent and would therefore hide it.
type fakeServer struct {
	in       io.Reader
	out      io.Writer
	received bytes.Buffer
	sent     bytes.Buffer
}

func (f *fakeServer) run(done chan<- struct{}, closeOut func()) {
	defer close(done)
	defer closeOut()
	r := bufio.NewReader(f.in)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			f.received.Write(line)
			resp := f.respond(line)
			if resp != "" {
				f.sent.WriteString(resp)
				if _, werr := f.out.Write([]byte(resp)); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// requestID pulls the id out of a request so responses carry the matching one, as a
// real server's would. Getting this wrong in a fake is worth guarding against: a
// response with a stale id is unmatchable, and the test would report a detection gap
// that exists only in the fixture.
var requestID = regexp.MustCompile(`"id"\s*:\s*(\d+)`)

func (f *fakeServer) respond(request []byte) string {
	id := "0"
	if m := requestID.FindSubmatch(request); m != nil {
		id = string(m[1])
	}
	switch {
	case bytes.Contains(request, []byte(`"initialize"`)):
		return `{"jsonrpc":"2.0","id":` + id + `,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"wiki","version":"3.2.0"}}}` + "\n"
	case bytes.Contains(request, []byte(`"tools/list"`)):
		return strings.Replace(listResult, `"id":2`, `"id":`+id, 1) + "\n"
	case bytes.Contains(request, []byte(`"tools/call"`)):
		return `{"jsonrpc":"2.0","id":` + id + `,"result":{"content":[{"type":"text","text":"ünïcødé ☃ result"}]}}` + "\n"
	}
	return ""
}

// TestProxyIsByteExactBothDirections is the inertness guarantee at the process
// boundary: whatever the client sends reaches the server unchanged, whatever the
// server answers reaches the client unchanged, and nothing else is ever written to
// stdout. A stray byte here presents as a mysteriously broken MCP server, and the
// developer has no way to tell it was us.
func TestProxyIsByteExactBothDirections(t *testing.T) {
	f := newFixture(t, true)

	fromClient := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"2.1.271"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
		`{ "jsonrpc" : "2.0" , "id" : 3 , "method" : "tools/call" , "params" : { "name" : "search" } }` + "\n"

	toServerR, toServerW := io.Pipe()
	fromServerR, fromServerW := io.Pipe()
	server := &fakeServer{in: toServerR, out: fromServerW}
	serverDone := make(chan struct{})
	go server.run(serverDone, func() { fromServerW.Close() })

	var toClient bytes.Buffer
	p := &Proxy{
		FromClient: strings.NewReader(fromClient),
		ToServer:   toServerW,
		FromServer: fromServerR,
		ToClient:   &toClient,
		// Closing the server's stdin is what lets the wrapped process finish, which
		// is what ends the session.
		CloseServerIn: func() { toServerW.Close() },
		Analyzer:      f.an,
		Logger:        quietLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	<-serverDone

	if server.received.String() != fromClient {
		t.Errorf("client stream was altered on the way to the server:\n got: %q\nwant: %q", server.received.String(), fromClient)
	}
	if toClient.String() != server.sent.String() {
		t.Errorf("server stream was altered on the way to the client:\n got: %q\nwant: %q", toClient.String(), server.sent.String())
	}
	if !strings.Contains(toClient.String(), "ünïcødé ☃ result") {
		t.Error("multibyte content did not survive the relay")
	}

	// And the analysis still happened, off the forwarding path.
	reports := f.close(t)
	rep := reportFor(t, reports, TriggerToolsList)
	if len(rep.Tools) != 2 {
		t.Errorf("listing carried %d tools, want 2", len(rep.Tools))
	}
	if rep.ClientVersion != "2.1.271" {
		t.Errorf("client version = %q", rep.ClientVersion)
	}
	if rep.ServerInfo.Version != "3.2.0" {
		t.Errorf("server version = %q", rep.ServerInfo.Version)
	}
	if st := f.an.Stats(); st.Calls != 1 {
		t.Errorf("tools/call count = %d, want 1", st.Calls)
	}
}

// TestProxyMatchesResponsesUnderLoad hammers the ordering guarantee: many
// request/response pairs answered as fast as the fake server can manage. Every
// listing must still be recognized, because an unmatched response is silent.
func TestProxyMatchesResponsesUnderLoad(t *testing.T) {
	f := newFixture(t, true)

	var reqs strings.Builder
	const rounds = 50
	for i := 0; i < rounds; i++ {
		fmt.Fprintf(&reqs, `{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`+"\n", i)
	}

	toServerR, toServerW := io.Pipe()
	fromServerR, fromServerW := io.Pipe()
	// Responds immediately to every request, which is the timing that exposes an
	// observe-after-forward ordering bug.
	server := &fakeServer{in: toServerR, out: fromServerW}
	serverDone := make(chan struct{})
	go server.run(serverDone, func() { fromServerW.Close() })

	p := &Proxy{
		FromClient:    strings.NewReader(reqs.String()),
		ToServer:      toServerW,
		FromServer:    fromServerR,
		ToClient:      io.Discard,
		CloseServerIn: func() { toServerW.Close() },
		Analyzer:      f.an,
		Logger:        quietLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	<-serverDone
	reports := f.close(t)

	var listings int
	for _, r := range reports {
		if r.Trigger == TriggerToolsList {
			listings++
		}
	}
	st := f.an.Stats()
	// Frames may legitimately be dropped under flood (the queue is bounded and the
	// relay must never block), so the assertion is that nothing was silently lost:
	// every listing either produced a report or was counted as a dropped frame.
	if int64(listings)+st.FramesDropped < rounds {
		t.Errorf("%d listings reported and %d frames dropped, which does not account for %d requests",
			listings, st.FramesDropped, rounds)
	}
	if listings == 0 {
		t.Error("no listing was recognized at all; responses are not being matched to requests")
	}
}

// TestProxySurvivesAHostileServer: garbage, an enormous frame and a batch all go
// through untouched. The interposer declines to parse them and forwards anyway,
// because a server the interposer cannot understand is still a server the developer
// is using.
func TestProxySurvivesAHostileServer(t *testing.T) {
	f := newFixture(t, true)

	hostile := "not json at all\n" +
		`[{"jsonrpc":"2.0","id":1,"result":{}}]` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"padding":"` + strings.Repeat("x", 256<<10) + `"}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` + "\n"

	var toServer, toClient bytes.Buffer
	p := &Proxy{
		FromClient: strings.NewReader(""),
		ToServer:   &toServer,
		FromServer: strings.NewReader(hostile),
		ToClient:   &toClient,
		Analyzer:   f.an,
		Logger:     quietLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if toClient.String() != hostile {
		t.Error("hostile input was not forwarded verbatim")
	}

	reports := f.close(t)
	// The notification still got through the noise.
	reportFor(t, reports, TriggerNotification)
	if st := f.an.Stats(); st.FramesUnparsed != 2 {
		t.Errorf("FramesUnparsed = %d, want 2", st.FramesUnparsed)
	}
}

// failingWriter stands in for a client that has gone away mid-session.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteClosed }

var errWriteClosed = writeClosedError{}

type writeClosedError struct{}

func (writeClosedError) Error() string { return "client closed" }

func TestProxyReportsATransportError(t *testing.T) {
	f := newFixture(t, true)
	defer f.close(t)

	p := &Proxy{
		FromClient: strings.NewReader(""),
		ToServer:   &bytes.Buffer{},
		FromServer: strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"),
		ToClient:   failingWriter{},
		Analyzer:   f.an,
		Logger:     quietLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Run(ctx); err == nil {
		t.Error("a write failure to the client should surface: the peer is gone")
	}
}
