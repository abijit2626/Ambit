package collector

import (
	"fmt"
	"testing"
)

func TestFPSetReportsOnlyTheFirstSighting(t *testing.T) {
	s := newFPSet(4)
	if !s.add("a") {
		t.Error("first sighting of a was reported as a repeat")
	}
	if s.add("a") {
		t.Error("second sighting of a was reported as new")
	}
	if !s.add("b") {
		t.Error("a different fingerprint was reported as a repeat")
	}
}

// Forgetting may cost a repeat sighting; it must never make a new fingerprint look like a repeat.
func TestFPSetEvictsTheOldestAndForgetsOnlyThat(t *testing.T) {
	s := newFPSet(3)
	for _, fp := range []string{"a", "b", "c"} {
		s.add(fp)
	}
	if !s.add("d") { // evicts a
		t.Fatal("d was reported as a repeat")
	}
	if !s.add("a") { // a was forgotten, so it is sent again; this evicts b
		t.Error("a was evicted, so its next sighting must be reported as new")
	}
	if s.add("c") || s.add("d") || s.add("a") {
		t.Error("c, d and a are still remembered and must be reported as repeats")
	}
	if !s.add("b") {
		t.Error("b was evicted by a's return and must be reported as new")
	}
}

func TestFPSetNeverGrowsPastItsCapacity(t *testing.T) {
	const capacity = 8
	s := newFPSet(capacity)
	for i := 0; i < 1000; i++ {
		s.add(fmt.Sprintf("fp%d", i))
		if len(s.seen) > capacity || len(s.order) > capacity {
			t.Fatalf("after %d fingerprints the set holds %d (order %d), cap %d", i+1, len(s.seen), len(s.order), capacity)
		}
	}
}

// An unexpected capacity must fail towards sending, not towards silence.
func TestFPSetWithoutCapacityRemembersNothing(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		s := newFPSet(capacity)
		for i := 0; i < 3; i++ {
			if !s.add("a") {
				t.Errorf("cap %d: repeat %d was suppressed", capacity, i)
			}
		}
	}
}
