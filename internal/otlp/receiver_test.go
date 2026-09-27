package otlp

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

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type sinkRecorder struct {
	mu   sync.Mutex
	recs []Record
}

func (s *sinkRecorder) sink(rs []Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rs...)
}

func (s *sinkRecorder) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}

func start(t *testing.T, sr *sinkRecorder) (string, *Server) {
	t.Helper()
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Sink: sr.sink, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return "http://" + ln.Addr().String(), s
}

// A realistic OTLP/JSON logs payload shaped like Claude Code's tool_decision
// event, including resource attributes that must be merged onto each record.
const logsPayload = `{
  "resourceLogs": [{
    "resource": {"attributes": [
      {"key": "service.name", "value": {"stringValue": "claude-code"}},
      {"key": "user.id", "value": {"stringValue": "u_1a2b"}},
      {"key": "organization.id", "value": {"stringValue": "o_9x8y"}}
    ]},
    "scopeLogs": [{
      "scope": {"name": "com.anthropic.claude_code"},
      "logRecords": [
        {
          "timeUnixNano": "1790000000000000000",
          "severityText": "INFO",
          "body": {"stringValue": "claude_code.tool_decision"},
          "attributes": [
            {"key": "session.id", "value": {"stringValue": "sess_d1"}},
            {"key": "tool_name", "value": {"stringValue": "Bash"}},
            {"key": "tool_use_id", "value": {"stringValue": "toolu_a"}},
            {"key": "decision", "value": {"stringValue": "accept"}},
            {"key": "source", "value": {"stringValue": "config"}}
          ]
        },
        {
          "timeUnixNano": "1790000001000000000",
          "eventName": "claude_code.tool_result",
          "body": {"stringValue": ""},
          "attributes": [
            {"key": "session.id", "value": {"stringValue": "sess_d1"}},
            {"key": "tool_name", "value": {"stringValue": "mcp__github__create_issue"}},
            {"key": "mcp_server.name", "value": {"stringValue": "github"}},
            {"key": "mcp_tool.name", "value": {"stringValue": "create_issue"}},
            {"key": "success", "value": {"boolValue": true}},
            {"key": "duration_ms", "value": {"intValue": "412"}}
          ]
        }
      ]
    }]
  }]
}`

func TestDecodeLogs(t *testing.T) {
	recs, err := Decode(SignalLogs, []byte(logsPayload))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	first := recs[0]
	if first.Name != "claude_code.tool_decision" {
		t.Errorf("Name = %q, want the body string when eventName is absent", first.Name)
	}
	if first.SessionID() != "sess_d1" {
		t.Errorf("SessionID() = %q", first.SessionID())
	}
	if first.Attr("tool_name") != "Bash" {
		t.Errorf("tool_name = %q", first.Attr("tool_name"))
	}
	// Resource attributes must be merged onto every record, or user and org
	// attribution is lost for all but the first.
	if first.Attr("user.id") != "u_1a2b" || first.Attr("organization.id") != "o_9x8y" {
		t.Errorf("resource attributes not merged: %v", first.Attrs)
	}
	if !first.TS.Equal(time.Unix(0, 1790000000000000000).UTC()) {
		t.Errorf("TS = %v, want the timeUnixNano value", first.TS)
	}

	second := recs[1]
	if second.Name != "claude_code.tool_result" {
		t.Errorf("Name = %q, want eventName to win over an empty body", second.Name)
	}
	if second.Attr("mcp_server.name") != "github" {
		t.Errorf("mcp_server.name = %q", second.Attr("mcp_server.name"))
	}
	// Non-string AnyValue variants must survive stringification.
	if second.Attr("success") != "true" {
		t.Errorf("boolValue = %q, want \"true\"", second.Attr("success"))
	}
	if second.Attr("duration_ms") != "412" {
		t.Errorf("intValue = %q, want \"412\"", second.Attr("duration_ms"))
	}
}

func TestAttrPrefersFirstPresentKey(t *testing.T) {
	r := Record{Attrs: map[string]string{"session_id": "old-spelling"}}
	if got := r.SessionID(); got != "old-spelling" {
		t.Errorf("SessionID() = %q; a renamed attribute must still resolve", got)
	}
	r2 := Record{Attrs: map[string]string{"session.id": "new", "session_id": "old"}}
	if got := r2.SessionID(); got != "new" {
		t.Errorf("SessionID() = %q, want the first candidate key to win", got)
	}
	if got := (Record{}).Attr("anything"); got != "" {
		t.Errorf("Attr on empty record = %q, want \"\"", got)
	}
}

func TestDecodeAnyValueVariants(t *testing.T) {
	payload := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{
	  "body":{"stringValue":"e"},
	  "attributes":[
	    {"key":"d","value":{"doubleValue":"1.5"}},
	    {"key":"arr","value":{"arrayValue":{"values":[{"stringValue":"a"},{"stringValue":"b"}]}}},
	    {"key":"kv","value":{"kvlistValue":{"values":[{"key":"k","value":{"stringValue":"v"}}]}}},
	    {"key":"empty","value":{}}
	  ]}]}]}]}`
	recs, err := Decode(SignalLogs, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	a := recs[0]
	if a.Attr("d") != "1.5" {
		t.Errorf("doubleValue = %q", a.Attr("d"))
	}
	if a.Attrs["arr"] != "a,b" {
		t.Errorf("arrayValue = %q", a.Attrs["arr"])
	}
	if a.Attrs["kv"] != "k=v" {
		t.Errorf("kvlistValue = %q", a.Attrs["kv"])
	}
	if a.Attrs["empty"] != "" {
		t.Errorf("empty AnyValue = %q, want \"\"", a.Attrs["empty"])
	}
}

// TestDecodeMetricsAndTracesAreSummarized documents the scope decision: the count
// is what the discrepancy detector needs, and the hook stream already carries
// tool-call detail with better fidelity.
func TestDecodeMetricsAndTracesAreSummarized(t *testing.T) {
	for _, sig := range []Signal{SignalMetrics, SignalTraces} {
		recs, err := Decode(sig, []byte(`{"resourceMetrics":[{"scopeMetrics":[]}]}`))
		if err != nil {
			t.Fatalf("%s: %v", sig, err)
		}
		if len(recs) != 1 || recs[0].Signal != sig {
			t.Errorf("%s: got %d records, want 1 summary record", sig, len(recs))
		}
	}
	// Malformed JSON must still be reported, so a misconfigured exporter is not
	// silently counted as healthy.
	if _, err := Decode(SignalMetrics, []byte("{not json")); err == nil {
		t.Error("malformed metrics payload should return an error")
	}
}

func TestServeLogsEndpoint(t *testing.T) {
	sr := &sinkRecorder{}
	url, srv := start(t, sr)

	resp, err := http.Post(url+"/v1/logs", "application/json", bytes.NewReader([]byte(logsPayload)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// An empty JSON object is a valid Export*ServiceResponse with no partial
	// success; anything else makes the exporter think something went wrong.
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("response = %v, want {}", body)
	}
	if sr.count() != 2 {
		t.Errorf("sink got %d records, want 2", sr.count())
	}
	if st := srv.Stats(); st.Records != 2 || st.Requests != 1 {
		t.Errorf("Stats = %+v, want 1 request / 2 records", st)
	}
}

// TestProtobufIsRejectedLoudly is the important one. A silent decode failure
// would look like "OTel is configured" while nothing was ever received — exactly
// the blind spot the second stream exists to close. 415 also tells the exporter
// this will never work rather than inviting a retry loop.
func TestProtobufIsRejectedLoudly(t *testing.T) {
	sr := &sinkRecorder{}
	url, srv := start(t, sr)

	resp, err := http.Post(url+"/v1/logs", "application/x-protobuf", bytes.NewReader([]byte{0x0a, 0x00}))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415 for protobuf", resp.StatusCode)
	}
	if srv.Stats().Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", srv.Stats().Rejected)
	}
	if sr.count() != 0 {
		t.Error("a rejected export must not reach the sink")
	}
}

func TestJSONContentTypeWithCharset(t *testing.T) {
	sr := &sinkRecorder{}
	url, _ := start(t, sr)
	resp, err := http.Post(url+"/v1/logs", "application/json; charset=utf-8", bytes.NewReader([]byte(logsPayload)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; a charset parameter must not be read as a different encoding", resp.StatusCode)
	}
}

// TestMalformedPayloadReturns200: an OTLP client retries on an error response,
// and a retry loop on a payload we cannot parse is worse than dropping it.
func TestMalformedPayloadReturns200(t *testing.T) {
	sr := &sinkRecorder{}
	url, srv := start(t, sr)
	resp, err := http.Post(url+"/v1/logs", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 to avoid a retry loop", resp.StatusCode)
	}
	if srv.Stats().DecodeErrs != 1 {
		t.Errorf("DecodeErrs = %d, want 1", srv.Stats().DecodeErrs)
	}
}

func TestAllThreeSignalEndpointsExist(t *testing.T) {
	sr := &sinkRecorder{}
	url, _ := start(t, sr)
	for _, path := range []string{"/v1/logs", "/v1/metrics", "/v1/traces"} {
		resp, err := http.Post(url+path, "application/json", bytes.NewReader([]byte(`{}`)))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s status = %d, want 200: all three must exist or the exporter logs errors", path, resp.StatusCode)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	sr := &sinkRecorder{}
	url, _ := start(t, sr)
	resp, err := http.Get(url + "/v1/logs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", resp.StatusCode)
	}
}

func TestEmptyPayloadDoesNotCallSink(t *testing.T) {
	sr := &sinkRecorder{}
	url, _ := start(t, sr)
	resp, _ := http.Post(url+"/v1/logs", "application/json", bytes.NewReader([]byte(`{"resourceLogs":[]}`)))
	resp.Body.Close()
	if sr.count() != 0 {
		t.Errorf("sink called with %d records for an empty payload", sr.count())
	}
}

func TestNanosFallbackToObservedTime(t *testing.T) {
	payload := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[
	  {"observedTimeUnixNano":"1790000009000000000","body":{"stringValue":"e"}}]}]}]}`
	recs, err := Decode(SignalLogs, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !recs[0].TS.Equal(time.Unix(0, 1790000009000000000).UTC()) {
		t.Errorf("TS = %v, want the observedTimeUnixNano fallback", recs[0].TS)
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	if ln, err := Listen("0.0.0.0:0"); err == nil {
		ln.Close()
		t.Error("the OTLP receiver must refuse a non-loopback bind")
	}
}
