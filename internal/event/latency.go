package event

import "sort"

type LatencyBucket struct {
	LEUS int64 `json:"le_us"`
	N    int64 `json:"n"`
}

type Latency struct {
	Count      int64           `json:"count"`
	OverBudget int64           `json:"over_budget"`
	BudgetUS   int64           `json:"budget_us"`
	MaxUS      int64           `json:"max_us"`
	P50US      int64           `json:"p50_us"`
	P95US      int64           `json:"p95_us"`
	P99US      int64           `json:"p99_us"`
	Buckets    []LatencyBucket `json:"buckets"`
	Overflow   int64           `json:"overflow"`
}

func (l Latency) Quantile(q float64) int64 {
	var total int64
	for _, b := range l.Buckets {
		total += b.N
	}
	total += l.Overflow
	if total == 0 {
		return 0
	}
	rank := int64(q * float64(total))
	if float64(rank) < q*float64(total) {
		rank++
	}
	if rank < 1 {
		rank = 1
	}
	var cum int64
	for _, b := range l.Buckets {
		cum += b.N
		if cum >= rank {
			if l.MaxUS > 0 && l.MaxUS < b.LEUS {
				return l.MaxUS
			}
			return b.LEUS
		}
	}
	return l.MaxUS
}

func MergeLatency(ls ...Latency) (Latency, bool) {
	var out Latency
	sameBudget := true
	byLE := map[int64]int64{}
	for i, l := range ls {
		if i == 0 {
			out.BudgetUS = l.BudgetUS
		} else if l.BudgetUS != out.BudgetUS {
			sameBudget = false
		}
		out.Count += l.Count
		out.OverBudget += l.OverBudget
		out.Overflow += l.Overflow
		if l.MaxUS > out.MaxUS {
			out.MaxUS = l.MaxUS
		}
		for _, b := range l.Buckets {
			byLE[b.LEUS] += b.N
		}
	}
	for le, n := range byLE {
		out.Buckets = append(out.Buckets, LatencyBucket{LEUS: le, N: n})
	}
	sort.Slice(out.Buckets, func(i, j int) bool { return out.Buckets[i].LEUS < out.Buckets[j].LEUS })
	out.P50US = out.Quantile(0.50)
	out.P95US = out.Quantile(0.95)
	out.P99US = out.Quantile(0.99)
	return out, sameBudget
}
