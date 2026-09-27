package hook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// maxBodyBytes caps an inbound hook body. Tool results can be large — Claude
// Code's own OTel content cap is 60 KB by default — and an unbounded read on the
// synchronous hook path is a memory and latency hazard. Oversized bodies are
// truncated, not rejected: losing some content is better than losing the event.
const maxBodyBytes = 4 << 20 // 4 MiB

// Handler turns a payload into whatever agentd does with it. Implementations
// must not block: they are called on the hook's synchronous path.
type Handler interface {
	Handle(*Payload)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(*Payload)

func (f HandlerFunc) Handle(p *Payload) { f(p) }

// Decider produces the response for an event. In M0 the only implementation is
// ObserveOnly.
type Decider interface {
	Decide(*Payload) *Response
}

// ObserveOnly returns no decision for every event.
//
// This is what makes M0 inert. Claude Code's pipeline is
// PreToolUse hook -> deny rules -> allow rules -> ask rules -> permission mode,
// and an empty response means the hook expressed no opinion, so every subsequent
// layer behaves exactly as it would with no hook installed. Returning "allow"
// here would be wrong even though it sounds equivalent: it suppresses the
// permission prompt a developer would otherwise see.
type ObserveOnly struct{}

func (ObserveOnly) Decide(*Payload) *Response { return &Response{} }

// Server serves hook events on a loopback listener.
type Server struct {
	handler Handler
	decider Decider
	log     *slog.Logger
	srv     *http.Server

	// Budget is the latency target. Exceeding it is logged, because the hook
	// path sits in front of every tool call on the endpoint and a regression
	// here is felt by every developer at once.
	Budget time.Duration
}

// Options configure the server.
type Options struct {
	// Addr must be a loopback address. agentd decides locally precisely so that
	// no fleet-wide network dependency sits in the critical path.
	Addr    string
	Handler Handler
	Decider Decider
	Logger  *slog.Logger
	Budget  time.Duration
}

func NewServer(opts Options) (*Server, error) {
	if opts.Handler == nil {
		return nil, errors.New("hook: Handler is required")
	}
	if opts.Decider == nil {
		opts.Decider = ObserveOnly{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Budget <= 0 {
		opts.Budget = 5 * time.Millisecond
	}
	s := &Server{
		handler: opts.Handler,
		decider: opts.Decider,
		log:     opts.Logger,
		Budget:  opts.Budget,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hook", s.serveHook)
	mux.HandleFunc("/healthz", s.serveHealth)
	s.srv = &http.Server{
		Addr:    opts.Addr,
		Handler: mux,
		// Generous relative to the 5ms budget: these bound a pathological client,
		// not normal operation.
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Serve listens and serves until the context is cancelled.
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

// ValidateLoopback reports whether addr is a loopback bind address.
//
// Binding off-loopback would expose a decision endpoint for the agent fleet to
// anything on the network, and would put remote latency in the tool-call path.
// Kept separate from Listen so the policy is testable without depending on the
// host having a working stack for the address family.
func ValidateLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("hook: listener must bind a loopback address; " + addr + " is not loopback")
	}
	return nil
}

// Listen opens a loopback listener, refusing any non-loopback bind.
func Listen(addr string) (net.Listener, error) {
	if err := ValidateLoopback(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

func (s *Server) serveHook(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		// Respond with an empty decision rather than an error: a failure in
		// agentd must not fail the tool call in M0.
		s.log.Warn("hook body read failed", "err", err)
		s.respond(w, &Response{}, start)
		return
	}

	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		s.log.Warn("hook body parse failed", "err", err, "bytes", len(body))
		s.respond(w, &Response{}, start)
		return
	}

	// Decide first, then hand off. The handler is async by contract, so the
	// response is not waiting on any event processing.
	resp := s.decider.Decide(&p)
	s.handler.Handle(&p)
	s.respond(w, resp, start)
}

func (s *Server) respond(w http.ResponseWriter, resp *Response, start time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if resp == nil {
		resp = &Response{}
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Warn("hook response write failed", "err", err)
	}
	if d := time.Since(start); d > s.Budget {
		s.log.Warn("hook response exceeded latency budget", "took", d, "budget", s.Budget)
	}
}

func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
