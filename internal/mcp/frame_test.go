package mcp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type recorder struct {
	buf    bytes.Buffer
	order  []string
	flush  int
	failOn int
	writes int
}

func (r *recorder) Write(p []byte) (int, error) {
	r.writes++
	if r.failOn > 0 && r.writes >= r.failOn {
		return 0, errors.New("write failed")
	}
	r.order = append(r.order, "write:"+strings.TrimSpace(string(p)))
	return r.buf.Write(p)
}

func (r *recorder) Flush() error {
	r.flush++
	return nil
}

func TestRelayIsByteExact(t *testing.T) {

	in := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n" +
		"{ \"jsonrpc\" : \"2.0\" ,  \"id\" : 2 }\n" +
		"\n" +
		"{\"note\":\"ünïcødé ☃\"}\n" +
		"{\"trailing\":\"no newline\"}"

	var out bytes.Buffer
	if err := Relay(&out, strings.NewReader(in), ForwardFirst, nil); err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if out.String() != in {
		t.Errorf("relay altered the stream:\n got: %q\nwant: %q", out.String(), in)
	}
}

func TestRelayForwardsBeforeObserving(t *testing.T) {
	r := &recorder{}
	in := "{\"id\":1}\n{\"id\":2}\n"

	if err := Relay(r, strings.NewReader(in), ForwardFirst, func(f Frame) {
		r.order = append(r.order, "observe:"+strings.TrimSpace(string(f.Raw)))
	}); err != nil {
		t.Fatalf("Relay: %v", err)
	}

	want := []string{
		`write:{"id":1}`, `observe:{"id":1}`,
		`write:{"id":2}`, `observe:{"id":2}`,
	}
	if len(r.order) != len(want) {
		t.Fatalf("order = %v, want %v", r.order, want)
	}
	for i := range want {
		if r.order[i] != want[i] {
			t.Errorf("order[%d] = %q, want %q (full: %v)", i, r.order[i], want[i], r.order)
		}
	}
	if r.flush == 0 {
		t.Error("relay never flushed; a buffered writer would hold a request until its buffer filled, which on a request/response protocol is a hang")
	}
}

func TestRelayReportsTruncatedFinalFrame(t *testing.T) {
	var got []Frame
	if err := Relay(io.Discard, strings.NewReader("{\"a\":1}\n{\"b\":2}"), ForwardFirst, func(f Frame) {
		got = append(got, f)
	}); err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d frames, want 2", len(got))
	}
	if got[0].Truncated {
		t.Error("first frame reported truncated; it ended with a newline")
	}
	if !got[1].Truncated {
		t.Error("final frame without a newline should report Truncated so a caller can tell a clean shutdown from a cut-off one")
	}
}

func TestRelayReturnsWriteError(t *testing.T) {
	r := &recorder{failOn: 2}
	err := Relay(r, strings.NewReader("{\"a\":1}\n{\"b\":2}\n"), ForwardFirst, nil)
	if err == nil {
		t.Fatal("want a write error: the peer is gone and the caller has to know")
	}
}

func TestRelayHandlesFrameLargerThanBuffer(t *testing.T) {
	big := `{"jsonrpc":"2.0","result":"` + strings.Repeat("x", 512<<10) + `"}`
	var out bytes.Buffer
	var observed int
	if err := Relay(&out, strings.NewReader(big+"\n"), ForwardFirst, func(Frame) { observed++ }); err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if out.String() != big+"\n" {
		t.Errorf("large frame was not forwarded intact: got %d bytes, want %d", out.Len(), len(big)+1)
	}
	if observed != 1 {
		t.Errorf("observed %d frames, want 1", observed)
	}
}

func TestParseRejectsBatchAndEmpty(t *testing.T) {
	if _, err := Parse([]byte(`[{"jsonrpc":"2.0","id":1}]`)); !errors.Is(err, ErrBatch) {
		t.Errorf("batch frame: err = %v, want ErrBatch", err)
	}
	if _, err := Parse([]byte("   \n")); err == nil {
		t.Error("empty frame should not parse")
	}
	if _, err := Parse([]byte(`{"jsonrpc":"2.0"`)); err == nil {
		t.Error("truncated JSON should not parse")
	}
}

func TestMessageClassification(t *testing.T) {
	req, err := Parse([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	if req.IsResponse() || req.IsNotification() {
		t.Error("a request with an id is neither a response nor a notification")
	}
	if req.IDKey() != "7" {
		t.Errorf("IDKey = %q, want \"7\"", req.IDKey())
	}

	spaced, err := Parse([]byte(`{"jsonrpc":"2.0","id" : "abc" ,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("parse spaced: %v", err)
	}
	if spaced.IDKey() != `"abc"` {
		t.Errorf("IDKey = %q, want %q", spaced.IDKey(), `"abc"`)
	}

	resp, err := Parse([]byte(`{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}`))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !resp.IsResponse() {
		t.Error("result with an id should classify as a response")
	}

	notif, err := Parse([]byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))
	if err != nil {
		t.Fatalf("parse notification: %v", err)
	}
	if !notif.IsNotification() {
		t.Error("method with no id should classify as a notification")
	}
}

func TestParseInitialize(t *testing.T) {
	info, err := ParseInitializeResult([]byte(`{"protocolVersion":"2025-06-18","serverInfo":{"name":"github","version":"1.4.0"}}`))
	if err != nil {
		t.Fatalf("ParseInitializeResult: %v", err)
	}
	if info.Name != "github" || info.Version != "1.4.0" || info.ProtocolVersion != "2025-06-18" {
		t.Errorf("info = %+v", info)
	}

	client, err := ParseInitializeParams([]byte(`{"clientInfo":{"name":"claude-code","version":"2.1.271"}}`))
	if err != nil {
		t.Fatalf("ParseInitializeParams: %v", err)
	}
	if client.Name != "claude-code" || client.Version != "2.1.271" {
		t.Errorf("client = %+v", client)
	}
}

func TestRelayObserveFirstRecordsBeforeForwarding(t *testing.T) {
	r := &recorder{}
	if err := Relay(r, strings.NewReader("{\"id\":1}\n"), ObserveFirst, func(f Frame) {
		r.order = append(r.order, "observe:"+strings.TrimSpace(string(f.Raw)))
	}); err != nil {
		t.Fatalf("Relay: %v", err)
	}
	want := []string{`observe:{"id":1}`, `write:{"id":1}`}
	if len(r.order) != len(want) || r.order[0] != want[0] || r.order[1] != want[1] {
		t.Errorf("order = %v, want %v", r.order, want)
	}

	if strings.TrimSpace(r.buf.String()) != `{"id":1}` {
		t.Errorf("frame not forwarded: %q", r.buf.String())
	}
}
