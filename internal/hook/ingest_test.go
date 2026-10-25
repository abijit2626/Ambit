package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// slowRecorder is a handler that takes a while per payload and records what it saw, per session.
type slowRecorder struct {
	delay time.Duration
	mu    sync.Mutex
	seen  map[string][]string
	live  map[string]int
	peak  map[string]int
}

func newSlowRecorder(delay time.Duration) *slowRecorder {
	return &slowRecorder{delay: delay, seen: map[string][]string{}, live: map[string]int{}, peak: map[string]int{}}
}

func (r *slowRecorder) Handle(p *Payload) {
	r.mu.Lock()
	r.live[p.SessionID]++
	if r.live[p.SessionID] > r.peak[p.SessionID] {
		r.peak[p.SessionID] = r.live[p.SessionID]
	}
	r.mu.Unlock()
	time.Sleep(r.delay)
	r.mu.Lock()
	r.seen[p.SessionID] = append(r.seen[p.SessionID], p.ToolUseID)
	r.live[p.SessionID]--
	r.mu.Unlock()
}

func (r *slowRecorder) snapshot() (map[string][]string, map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string][]string{}
	for k, v := range r.seen {
		seen[k] = append([]string(nil), v...)
	}
	peak := map[string]int{}
	for k, v := range r.peak {
		peak[k] = v
	}
	return seen, peak
}

// Within one session the handler sees payloads in the order they arrived, one at a time, even though each
// response goes out before its payload is handled.
func TestOneSessionIsHandledInArrivalOrderAndOneAtATime(t *testing.T) {
	r := newSlowRecorder(2 * time.Millisecond)
	in := newIngest(r, 0)
	for i := 0; i < 40; i++ {
		in.enqueue(&Payload{SessionID: "s1", ToolUseID: fmt.Sprint(i)})
	}
	if !in.wait(5 * time.Second) {
		t.Fatal("ingest did not finish")
	}
	seen, peak := r.snapshot()
	if len(seen["s1"]) != 40 {
		t.Fatalf("handled %d payloads, want 40", len(seen["s1"]))
	}
	for i, id := range seen["s1"] {
		if id != fmt.Sprint(i) {
			t.Fatalf("payload %d handled as %s: a session's payloads must keep their order", i, id)
		}
	}
	if peak["s1"] != 1 {
		t.Errorf("up to %d payloads of one session were in the handler at once, want 1", peak["s1"])
	}
}

// Sessions do not wait for each other.
func TestDifferentSessionsAreHandledInParallel(t *testing.T) {
	r := newSlowRecorder(50 * time.Millisecond)
	in := newIngest(r, 0)
	start := time.Now()
	for _, s := range []string{"a", "b", "c", "d"} {
		in.enqueue(&Payload{SessionID: s, ToolUseID: "x"})
	}
	if !in.wait(5 * time.Second) {
		t.Fatal("ingest did not finish")
	}
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Errorf("four sessions of one payload each took %v; they should overlap", took)
	}
}

// A session that outruns its queue loses the excess, and the loss is counted rather than blocking anyone.
func TestSessionQueueOverflowIsCountedNotBlocking(t *testing.T) {
	r := newSlowRecorder(20 * time.Millisecond)
	in := newIngest(r, 3)
	start := time.Now()
	for i := 0; i < 20; i++ {
		in.enqueue(&Payload{SessionID: "s", ToolUseID: fmt.Sprint(i)})
	}
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Errorf("enqueueing 20 payloads blocked for %v", took)
	}
	if !in.wait(5 * time.Second) {
		t.Fatal("ingest did not finish")
	}
	if got := in.dropped.Load(); got == 0 {
		t.Error("nothing was counted as dropped with a queue of 3 and 20 payloads")
	}
	seen, _ := r.snapshot()
	if int64(len(seen["s"]))+in.dropped.Load() != 20 {
		t.Errorf("handled %d and dropped %d: together they must be all 20", len(seen["s"]), in.dropped.Load())
	}
}

// The response goes out before the handler has run, which is the point of the change.
func TestResponseDoesNotWaitForTheHandler(t *testing.T) {
	r := newSlowRecorder(300 * time.Millisecond)
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Handler: r, Decider: ObserveOnly{}, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx, ln) }()

	body, _ := json.Marshal(Payload{HookEventName: EvPostToolUse, SessionID: "s", ToolUseID: "slow"})
	start := time.Now()
	resp, err := http.Post("http://"+ln.Addr().String()+"/hook", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Errorf("the response took %v, but the handler sleeps 300ms: the response must not wait for it", took)
	}
	seen, _ := r.snapshot()
	if len(seen["s"]) != 0 {
		t.Error("the handler had already finished when the response came back")
	}
}

// Serve does not return until the payloads it accepted have been handled, so a shutdown does not lose them.
func TestShutdownWaitsForAcceptedPayloads(t *testing.T) {
	r := newSlowRecorder(200 * time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Handler: r, Decider: ObserveOnly{}, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	body, _ := json.Marshal(Payload{HookEventName: EvPostToolUse, SessionID: "s", ToolUseID: "last"})
	resp, err := http.Post("http://"+ln.Addr().String()+"/hook", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	seen, _ := r.snapshot()
	if len(seen["s"]) != 1 {
		t.Errorf("Serve returned with %d of the accepted payloads handled; it must wait for the one accepted", len(seen["s"]))
	}
}

func TestStatsReportTheQueueDrops(t *testing.T) {
	r := newSlowRecorder(time.Hour)
	s, err := NewServer(Options{Handler: r, Decider: ObserveOnly{}, Logger: quietLogger(), SessionQueue: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.ingest.enqueue(&Payload{SessionID: "stuck", ToolUseID: fmt.Sprint(i)})
	}
	if got := s.Stats().QueueDropped; got == 0 {
		t.Error("Stats.QueueDropped is zero with a queue of 1 and five payloads")
	}
}
