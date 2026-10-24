package hook

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"
)

func TestLatencyBucketsCountEveryResponseOnce(t *testing.T) {
	r := newLatencyRecorder(5 * time.Millisecond)
	for _, d := range []time.Duration{
		100 * time.Microsecond,
		250 * time.Microsecond,
		251 * time.Microsecond,
		5 * time.Millisecond,
		5*time.Millisecond + time.Microsecond,
		3 * time.Second,
	} {
		r.record(d)
	}
	s := r.snapshot()

	if s.Count != 6 {
		t.Errorf("count = %d, want 6", s.Count)
	}
	var sum int64
	for _, b := range s.Buckets {
		sum += b.N
	}
	if sum+s.Overflow != s.Count {
		t.Errorf("buckets %d + overflow %d != count %d", sum, s.Overflow, s.Count)
	}
	if s.Buckets[0].N != 2 {
		t.Errorf("le 250us bucket = %d, want 2: the bound is inclusive", s.Buckets[0].N)
	}
	if s.Overflow != 1 {
		t.Errorf("overflow = %d, want 1", s.Overflow)
	}
	if s.OverBudget != 2 {
		t.Errorf("over_budget = %d, want 2: exactly 5ms is within budget, 5.001ms and 3s are not", s.OverBudget)
	}
	if s.MaxUS != 3_000_000 {
		t.Errorf("max_us = %d, want 3000000", s.MaxUS)
	}
	if s.BudgetUS != 5000 {
		t.Errorf("budget_us = %d, want 5000", s.BudgetUS)
	}
}

func TestLatencyQuantileIsTheBucketUpperBound(t *testing.T) {
	r := newLatencyRecorder(5 * time.Millisecond)
	for i := 0; i < 98; i++ {
		r.record(300 * time.Microsecond)
	}
	r.record(4500 * time.Microsecond)
	r.record(20 * time.Millisecond)
	s := r.snapshot()

	if s.P50US != 500 {
		t.Errorf("p50 = %d, want 500 (the 250-500us bucket)", s.P50US)
	}
	if s.P99US != 5000 {
		t.Errorf("p99 = %d, want 5000: the 99th of 100 responses is the 4.5ms one", s.P99US)
	}
	if got := s.Quantile(1); got != 20000 {
		t.Errorf("p100 = %d, want 20000: clamped to the observed max, not the 25ms bound", got)
	}
}

func TestLatencyQuantileOfNothingIsZero(t *testing.T) {
	if got := newLatencyRecorder(time.Millisecond).snapshot().P99US; got != 0 {
		t.Errorf("p99 of no responses = %d, want 0", got)
	}
}

func TestLatencyQuantileInOverflowIsTheMax(t *testing.T) {
	r := newLatencyRecorder(time.Millisecond)
	r.record(4 * time.Second)
	if got := r.snapshot().P50US; got != 4_000_000 {
		t.Errorf("p50 = %d, want the 4s max when every response overflowed", got)
	}
}

func TestServerStatsCountResponsesAndUnparseableBodies(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Options{Handler: &capture{}, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	url := "http://" + ln.Addr().String()

	post(t, url, Payload{HookEventName: EvPreToolUse, SessionID: "s1"})
	post(t, url, Payload{HookEventName: EvPostToolUse, SessionID: "s1"})
	resp, err := http.Post(url+"/hook", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = http.Get(url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	st := s.Stats()
	if st.Latency.Count != 3 {
		t.Errorf("latency count = %d, want 3: every /hook response, the unparseable one included, and not /healthz", st.Latency.Count)
	}
	if st.ParseErrors != 1 {
		t.Errorf("parse errors = %d, want 1", st.ParseErrors)
	}
}
