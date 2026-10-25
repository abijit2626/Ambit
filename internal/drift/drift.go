// Package drift is the M4 goal-drift scorer: for a tool call that carries a provenance edge, it asks a
// model whether the action serves what the user asked for. It is off unless configured, because it
// sends the user's prompt and the tool call's arguments, redacted and truncated, to a model API, and
// every call costs money.
//
// The judge is asked the question the prototype in docs/03-detection.md measured (Claude Haiku 5.5 on
// AgentDojo, Claude 3.7 traces): RELATED or UNRELATED, nothing finer. A verdict maps to a score of 0 or
// 1 rather than to a probability the model would invent, so the threshold in the filter means "the
// judge said unrelated", and the measured rates are the rates this ships.
package drift

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ScorerVersion names the prompt and the verdict-to-score mapping. It changes whenever either does, so
// scores from different versions are never compared as if they were one measurement.
const ScorerVersion = "judge-v1"

// Request is what the judge sees: the user's latest prompt and the action under question. Both are
// already redacted by the caller.
type Request struct {
	Goal  string
	Tool  string
	Input string
}

type Judge interface {
	// Unrelated reports whether the action pursues something the user did not ask for.
	Unrelated(ctx context.Context, r Request) (bool, error)
	// Name identifies the judge in the score event, with the model it asks.
	Name() string
}

// ErrNoVerdict is a reply the scorer cannot read as RELATED or UNRELATED, including a refusal. No score
// is emitted for it: a missing score is honest, a guessed one is not.
var ErrNoVerdict = errors.New("drift: the judge gave no verdict")

type Options struct {
	Judge Judge
	// MaxPerHour caps judge calls, which bounds the cost on a busy endpoint. Calls over the cap are
	// skipped and counted, not queued.
	MaxPerHour int
	// Queue bounds requests waiting for a worker; a full queue drops and counts.
	Queue   int
	Workers int
	// Timeout bounds one judge call.
	Timeout time.Duration
	// MaxChars truncates the goal and the action before they leave the endpoint.
	MaxChars int
	Now      func() time.Time
	Logger   *slog.Logger
}

// Result is delivered to the job's callback when the judge gives a verdict.
type Result struct {
	Score  float64
	Scorer string
}

type job struct {
	req  Request
	done func(Result)
}

type Stats struct {
	Submitted   int64
	Judged      int64
	Unrelated   int64
	Dropped     int64
	RateLimited int64
	Errors      int64
}

type Scorer struct {
	opts  Options
	queue chan job
	wg    sync.WaitGroup

	mu          sync.Mutex
	windowStart time.Time
	inWindow    int
	closed      bool

	submitted, judged, unrelated, dropped, limited, errs atomic.Int64
}

func New(opts Options) (*Scorer, error) {
	if opts.Judge == nil {
		return nil, errors.New("drift: Judge is required")
	}
	if opts.MaxPerHour <= 0 {
		opts.MaxPerHour = 120
	}
	if opts.Queue <= 0 {
		opts.Queue = 64
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxChars <= 0 {
		opts.MaxChars = 4000
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Scorer{opts: opts, queue: make(chan job, opts.Queue)}
	for i := 0; i < opts.Workers; i++ {
		s.wg.Add(1)
		go s.work()
	}
	return s, nil
}

// Submit queues a request without waiting for it. It reports whether the request was queued; done runs
// on a worker goroutine, only when the judge gave a verdict.
func (s *Scorer) Submit(r Request, done func(Result)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	now := s.opts.Now()
	if now.Sub(s.windowStart) >= time.Hour {
		s.windowStart, s.inWindow = now, 0
	}
	if s.inWindow >= s.opts.MaxPerHour {
		s.limited.Add(1)
		return false
	}
	r.Goal = truncate(r.Goal, s.opts.MaxChars)
	r.Input = truncate(r.Input, s.opts.MaxChars)
	select {
	case s.queue <- job{req: r, done: done}:
		s.inWindow++
		s.submitted.Add(1)
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

func (s *Scorer) work() {
	defer s.wg.Done()
	for j := range s.queue {
		ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
		unrelated, err := s.opts.Judge.Unrelated(ctx, j.req)
		cancel()
		if err != nil {
			// bounded by MaxPerHour, so logging each one cannot flood the log
			s.errs.Add(1)
			s.opts.Logger.Warn("goal-drift judge gave no score", "err", err)
			continue
		}
		s.judged.Add(1)
		score := 0.0
		if unrelated {
			s.unrelated.Add(1)
			score = 1
		}
		if j.done != nil {
			j.done(Result{Score: score, Scorer: ScorerVersion + "/" + s.opts.Judge.Name()})
		}
	}
}

// Close stops taking requests and waits up to timeout for queued ones to finish. It reports whether
// they did.
func (s *Scorer) Close(timeout time.Duration) bool {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *Scorer) Stats() Stats {
	return Stats{
		Submitted:   s.submitted.Load(),
		Judged:      s.judged.Load(),
		Unrelated:   s.unrelated.Load(),
		Dropped:     s.dropped.Load(),
		RateLimited: s.limited.Load(),
		Errors:      s.errs.Load(),
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + " [truncated]"
}
