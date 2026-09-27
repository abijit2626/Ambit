// Package otlp receives Claude Code's OpenTelemetry export over OTLP/HTTP with
// JSON encoding.
//
// Why JSON and not gRPC or protobuf: Claude Code supports grpc, http/protobuf
// and http/json, and http/json is the only one decodable with the standard
// library. The alternatives would pull in grpc and protobuf runtimes for a
// daemon that currently has zero dependencies and ships to developer endpoints,
// which is a large supply-chain surface to add to a security tool. See
// docs/02-architecture.md.
//
// Why this exists at all: the OTel stream is the second, independent path. The
// hook stream dies with agentd's hook endpoint; OTel's destination is pinned in
// managed settings with developer-set variables removed. Losing one while the
// other continues is the discrepancy that makes suppression visible — that
// discrepancy, not either stream alone, is what detector D7 keys on.
//
// OTel data does NOT cross to Wazuh. It is content-rich and high-volume; it goes
// to the local spool and feeds the discrepancy counters.
package otlp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
)

// maxBodyBytes caps an inbound export. Claude Code's own content cap defaults to
// 60 KB per field and a batch carries many records, so this is generous while
// still bounding a pathological or hostile sender.
const maxBodyBytes = 16 << 20

// Signal identifies which OTLP endpoint a payload arrived on.
type Signal string

const (
	SignalLogs    Signal = "logs"
	SignalMetrics Signal = "metrics"
	SignalTraces  Signal = "traces"
)

// Record is one normalized observation extracted from an OTLP payload.
//
// Deliberately a neutral type: the receiver does not depend on the collector, so
// mapping a Record onto an event stays the collector's job and this package
// stays testable on its own.
type Record struct {
	Signal Signal
	// Name is the event name, from the log record's body or its event.name
	// attribute.
	Name string
	TS   time.Time
	// Attrs holds the flattened attributes. Values are stringified: the receiver
	// is a transport, and typed extraction belongs where the meaning is known.
	Attrs map[string]string
}

// Attr returns an attribute, preferring the first key present. Claude Code's
// attribute names have changed across versions, so callers name the candidates
// they accept rather than assuming one spelling.
func (r Record) Attr(keys ...string) string {
	for _, k := range keys {
		if v, ok := r.Attrs[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// SessionID returns the session this record belongs to.
func (r Record) SessionID() string { return r.Attr("session.id", "session_id") }

// Sink consumes decoded records. It must not block: the OTel exporter retries on
// slow responses, and a stalled receiver turns into memory pressure in the
// agent's exporter.
type Sink func([]Record)

// Server serves the three OTLP/HTTP signal endpoints.
type Server struct {
	sink Sink
	log  *slog.Logger
	srv  *http.Server

	// Counters, read by the health emitter for the discrepancy signal.
	stats Stats
}

// Stats reports what the receiver has seen.
type Stats struct {
	Requests    int64
	Records     int64
	DecodeErrs  int64
	Rejected    int64
	LastReceive time.Time
}

type Options struct {
	// Addr must be loopback. 127.0.0.1:4318 is the OTLP/HTTP default; 4317 is
	// gRPC and would be the wrong port for this receiver.
	Addr   string
	Sink   Sink
	Logger *slog.Logger
}

func NewServer(opts Options) (*Server, error) {
	if opts.Sink == nil {
		return nil, errors.New("otlp: Sink is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{sink: opts.Sink, log: opts.Logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", s.handler(SignalLogs))
	mux.HandleFunc("/v1/metrics", s.handler(SignalMetrics))
	mux.HandleFunc("/v1/traces", s.handler(SignalTraces))

	s.srv = &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	return s, nil
}

// Serve runs until the context is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()
	if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Listen opens the loopback listener for the receiver.
func Listen(addr string) (net.Listener, error) { return loopbackListen(addr) }

func (s *Server) Stats() Stats { return s.stats }

func (s *Server) handler(sig Signal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.stats.Requests++

		// Reject protobuf explicitly rather than failing to parse it. A silent
		// decode failure here would look like "OTel is configured" while
		// nothing was ever received, which is precisely the blind spot the
		// second stream exists to close.
		if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
			s.stats.Rejected++
			s.log.Error("OTLP export rejected: unsupported encoding",
				"content_type", ct, "signal", sig,
				"fix", "set OTEL_EXPORTER_OTLP_PROTOCOL=http/json")
			// 415 tells the exporter this will never work, rather than inviting
			// a retry loop.
			http.Error(w, `{"error":"only http/json is supported; set OTEL_EXPORTER_OTLP_PROTOCOL=http/json"}`,
				http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			s.stats.DecodeErrs++
			s.respondOK(w)
			return
		}

		records, err := Decode(sig, body)
		if err != nil {
			s.stats.DecodeErrs++
			s.log.Warn("OTLP decode failed", "signal", sig, "err", err, "bytes", len(body))
			// Still 200: an OTLP client that gets an error retries, and a retry
			// loop on a payload we cannot parse is worse than dropping it.
			s.respondOK(w)
			return
		}

		s.stats.Records += int64(len(records))
		s.stats.LastReceive = time.Now()
		if len(records) > 0 {
			s.sink(records)
		}
		s.respondOK(w)
	}
}

func (s *Server) respondOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// An empty JSON object is a valid Export*ServiceResponse with no partial
	// success, which is what the OTLP spec expects on full acceptance.
	_, _ = w.Write([]byte(`{}`))
}

func isJSONContentType(ct string) bool {
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			ct = ct[:i]
			break
		}
	}
	switch trimSpace(ct) {
	case "application/json", "application/x-ndjson":
		return true
	}
	return false
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// --- OTLP/JSON wire types -------------------------------------------------
//
// Only the fields needed to extract log records are modelled. Metrics and traces
// are accepted and counted but not deeply parsed: for detection purposes the log
// stream carries the tool_decision and tool_result events, while metrics are
// aggregates and traces duplicate what the hook stream already reports with
// better fidelity. Documented scope, not an oversight.

type exportLogs struct {
	ResourceLogs []struct {
		Resource  resource `json:"resource"`
		ScopeLogs []struct {
			LogRecords []logRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type resource struct {
	Attributes []keyValue `json:"attributes"`
}

type logRecord struct {
	TimeUnixNano         json.Number `json:"timeUnixNano"`
	ObservedTimeUnixNano json.Number `json:"observedTimeUnixNano"`
	SeverityText         string      `json:"severityText"`
	Body                 anyValue    `json:"body"`
	Attributes           []keyValue  `json:"attributes"`
	EventName            string      `json:"eventName"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue models the OTLP AnyValue union. Each variant is a distinct JSON key,
// so exactly one is populated.
type anyValue struct {
	StringValue *string      `json:"stringValue"`
	BoolValue   *bool        `json:"boolValue"`
	IntValue    *json.Number `json:"intValue"`
	DoubleValue *json.Number `json:"doubleValue"`
	ArrayValue  *struct {
		Values []anyValue `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *struct {
		Values []keyValue `json:"values"`
	} `json:"kvlistValue"`
}

// String renders an AnyValue as text. Attributes are stringified because this
// package is a transport: typed extraction belongs where the meaning is known.
func (v anyValue) String() string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	case v.IntValue != nil:
		return v.IntValue.String()
	case v.DoubleValue != nil:
		return v.DoubleValue.String()
	case v.ArrayValue != nil:
		out := ""
		for i, e := range v.ArrayValue.Values {
			if i > 0 {
				out += ","
			}
			out += e.String()
		}
		return out
	case v.KvlistValue != nil:
		out := ""
		for i, kv := range v.KvlistValue.Values {
			if i > 0 {
				out += ","
			}
			out += kv.Key + "=" + kv.Value.String()
		}
		return out
	}
	return ""
}

// Decode turns an OTLP/JSON payload into records.
//
// For metrics and traces it returns a single summary record rather than parsing
// the payload: the count is what the discrepancy detector needs, and modelling
// the full metric and span schemas would be a lot of surface for signal the hook
// stream already carries.
func Decode(sig Signal, body []byte) ([]Record, error) {
	if sig != SignalLogs {
		// Confirm it is at least well-formed JSON, so a misconfigured exporter
		// is still reported rather than silently counted as fine.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(body, &probe); err != nil {
			return nil, err
		}
		return []Record{{
			Signal: sig,
			Name:   "otlp." + string(sig),
			TS:     time.Now().UTC(),
			Attrs:  map[string]string{"bytes": strconv.Itoa(len(body))},
		}}, nil
	}

	var payload exportLogs
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	var out []Record
	for _, rl := range payload.ResourceLogs {
		resourceAttrs := flatten(rl.Resource.Attributes)
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				attrs := make(map[string]string, len(resourceAttrs)+len(lr.Attributes))
				for k, v := range resourceAttrs {
					attrs[k] = v
				}
				for k, v := range flatten(lr.Attributes).all() {
					attrs[k] = v
				}

				name := lr.EventName
				if name == "" {
					name = attrs["event.name"]
				}
				if name == "" {
					name = lr.Body.String()
				}

				out = append(out, Record{
					Signal: SignalLogs,
					Name:   name,
					TS:     nanosToTime(lr.TimeUnixNano, lr.ObservedTimeUnixNano),
					Attrs:  attrs,
				})
			}
		}
	}
	return out, nil
}

type attrMap map[string]string

func (a attrMap) all() map[string]string { return a }

func flatten(kvs []keyValue) attrMap {
	out := make(attrMap, len(kvs))
	for _, kv := range kvs {
		if kv.Key != "" {
			out[kv.Key] = kv.Value.String()
		}
	}
	return out
}

// nanosToTime prefers timeUnixNano and falls back to observedTimeUnixNano, which
// is what an SDK sets when the record carries no explicit timestamp.
func nanosToTime(primary, fallback json.Number) time.Time {
	for _, n := range []json.Number{primary, fallback} {
		if n == "" {
			continue
		}
		if v, err := strconv.ParseInt(n.String(), 10, 64); err == nil && v > 0 {
			return time.Unix(0, v).UTC()
		}
	}
	return time.Now().UTC()
}
