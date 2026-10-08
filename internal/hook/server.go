package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/abijit2626/ambit/internal/loopback"
	"time"
)

const maxBodyBytes = 4 << 20

type Handler interface {
	Handle(*Payload)
}

type HandlerFunc func(*Payload)

func (f HandlerFunc) Handle(p *Payload) { f(p) }

type Decider interface {
	Decide(*Payload) *Response
}

type ObserveOnly struct{}

func (ObserveOnly) Decide(*Payload) *Response { return &Response{} }

type Server struct {
	handler Handler
	decider Decider
	log     *slog.Logger
	srv     *http.Server

	Budget time.Duration
}

type Options struct {
	Addr    string
	Handler Handler
	Decider Decider
	Logger  *slog.Logger
	Budget  time.Duration

	Extra map[string]http.Handler
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
	for path, h := range opts.Extra {
		switch path {
		case "", "/hook", "/healthz":

			return nil, fmt.Errorf("hook: extra mount %q is reserved", path)
		}
		if h == nil {
			return nil, fmt.Errorf("hook: extra mount %q has a nil handler", path)
		}
		mux.Handle(path, h)
	}
	s.srv = &http.Server{
		Addr:    opts.Addr,
		Handler: mux,

		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
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

func ValidateLoopback(addr string) error { return loopback.Validate(addr) }

func Listen(addr string) (net.Listener, error) { return loopback.Listen(addr) }

func (s *Server) serveHook(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {

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
