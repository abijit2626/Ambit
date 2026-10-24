package event

import "testing"

func TestMergeLatencySumsRunsByBucketBound(t *testing.T) {
	a := Latency{Count: 3, OverBudget: 1, BudgetUS: 5000, MaxUS: 6000,
		Buckets: []LatencyBucket{{LEUS: 500, N: 2}, {LEUS: 7500, N: 1}}}
	b := Latency{Count: 2, BudgetUS: 5000, MaxUS: 400, Overflow: 0,
		Buckets: []LatencyBucket{{LEUS: 7500, N: 0}, {LEUS: 500, N: 2}}}

	m, same := MergeLatency(a, b)
	if !same {
		t.Error("same budget reported as different")
	}
	if m.Count != 5 || m.OverBudget != 1 || m.MaxUS != 6000 {
		t.Errorf("merged = %+v", m)
	}
	if len(m.Buckets) != 2 || m.Buckets[0] != (LatencyBucket{500, 4}) || m.Buckets[1] != (LatencyBucket{7500, 1}) {
		t.Errorf("buckets = %+v, want 500:4 then 7500:1", m.Buckets)
	}
	if m.P50US != 500 || m.P99US != 6000 {
		t.Errorf("p50 = %d, p99 = %d, want 500 and 6000 (clamped to max)", m.P50US, m.P99US)
	}
}

func TestMergeLatencyFlagsMixedBudgets(t *testing.T) {
	_, same := MergeLatency(Latency{BudgetUS: 5000}, Latency{BudgetUS: 10000})
	if same {
		t.Error("a 5ms and a 10ms budget merged as if over_budget meant the same thing")
	}
}

func TestMergeLatencyOfNothing(t *testing.T) {
	m, same := MergeLatency()
	if !same || m.Count != 0 || m.P99US != 0 {
		t.Errorf("merge of no runs = %+v, %v", m, same)
	}
}
