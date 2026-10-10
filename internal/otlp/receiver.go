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

const maxBodyBytes = 16 << 20

type Signal string

const (
	SignalLogs    Signal = "logs"
	SignalMetrics Signal = "metrics"
	SignalTraces  Signal = "traces"
)

type Record struct {
	Signal Signal

	Name string
	TS   time.Time

	Attrs map[string]string
}

func (r Record) Attr(keys ...string) string {
	for _, k := range keys {
		if v, ok := r.Attrs[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func (r Record) SessionID() string { return r.Attr("session.id", "session_id") }

type Sink func([]Record)

type Server struct {
	sink Sink
	log  *slog.Logger
	srv  *http.Server

	stats Stats
}

type Stats struct {
	Requests    int64
	Records     int64
	DecodeErrs  int64
	Rejected    int64
	LastReceive time.Time
}

type Options struct {
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

func Listen(addr string) (net.Listener, error) { return loopbackListen(addr) }

func (s *Server) Stats() Stats { return s.stats }

func (s *Server) handler(sig Signal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.stats.Requests++

		if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
			s.stats.Rejected++
			s.log.Error("OTLP export rejected: unsupported encoding",
				"content_type", ct, "signal", sig,
				"fix", "set OTEL_EXPORTER_OTLP_PROTOCOL=http/json")

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

func Decode(sig Signal, body []byte) ([]Record, error) {
	if sig != SignalLogs {

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
