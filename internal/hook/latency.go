package hook

import (
	"sync/atomic"
	"time"

	"github.com/abijit2626/ambit/internal/event"
)

var LatencyBoundsUS = []int64{
	250, 500, 1000, 2000, 3000, 4000, 5000, 7500,
	10000, 25000, 50000, 100000, 250000, 1000000,
}

type latencyRecorder struct {
	budget     time.Duration
	counts     []atomic.Int64
	overflow   atomic.Int64
	count      atomic.Int64
	overBudget atomic.Int64
	maxUS      atomic.Int64
}

func newLatencyRecorder(budget time.Duration) *latencyRecorder {
	return &latencyRecorder{budget: budget, counts: make([]atomic.Int64, len(LatencyBoundsUS))}
}

func (r *latencyRecorder) record(d time.Duration) {
	us := d.Microseconds()
	r.count.Add(1)
	if d > r.budget {
		r.overBudget.Add(1)
	}
	for {
		cur := r.maxUS.Load()
		if us <= cur || r.maxUS.CompareAndSwap(cur, us) {
			break
		}
	}
	for i, le := range LatencyBoundsUS {
		if us <= le {
			r.counts[i].Add(1)
			return
		}
	}
	r.overflow.Add(1)
}

func (r *latencyRecorder) snapshot() event.Latency {
	s := event.Latency{
		Count:      r.count.Load(),
		OverBudget: r.overBudget.Load(),
		BudgetUS:   r.budget.Microseconds(),
		MaxUS:      r.maxUS.Load(),
		Buckets:    make([]event.LatencyBucket, len(LatencyBoundsUS)),
		Overflow:   r.overflow.Load(),
	}
	for i, le := range LatencyBoundsUS {
		s.Buckets[i] = event.LatencyBucket{LEUS: le, N: r.counts[i].Load()}
	}
	s.P50US = s.Quantile(0.50)
	s.P95US = s.Quantile(0.95)
	s.P99US = s.Quantile(0.99)
	return s
}
