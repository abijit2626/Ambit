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

func TestFPSetForgetMakesTheNextSightingNew(t *testing.T) {
	s := newFPSet(4)
	s.add("a")
	s.forget("a")
	if !s.add("a") {
		t.Error("a was forgotten, so its next sighting must be reported as new")
	}
	if s.add("a") {
		t.Error("a was added again and must now be remembered")
	}
	s.forget("never-added") // must not panic or disturb anything
	if s.add("a") {
		t.Error("forgetting an unknown fingerprint disturbed a")
	}
}

// forget empties a ring slot. The slot must not later evict a fingerprint that was added again, or the set
// would forget something it still holds and send it twice.
func TestFPSetForgottenSlotDoesNotEvictAReaddedFingerprint(t *testing.T) {
	s := newFPSet(2)
	s.add("a")
	s.forget("a")
	s.add("b")
	s.add("a") // re-added: takes the emptied slot
	if s.add("a") {
		t.Fatal("a was re-added and must be remembered")
	}
	s.add("c") // full set: evicts the oldest slot, which holds b
	if s.add("a") {
		t.Error("a is still in the set; evicting b must not have removed it")
	}
	if !s.add("b") {
		t.Error("b was evicted and must be reported as new")
	}
}

// Whatever the order of adds and forgets, the set stays within its capacity and every fingerprint it
// reports as remembered is held in exactly one slot.
func TestFPSetStaysConsistentUnderAddAndForget(t *testing.T) {
	const capacity = 4
	s := newFPSet(capacity)
	seed := uint64(7)
	next := func(n int) int {
		seed = seed*6364136223846793005 + 1442695040888963407
		return int(seed>>33) % n
	}
	for i := 0; i < 5000; i++ {
		fp := fmt.Sprintf("fp%d", next(9))
		if next(3) == 0 {
			s.forget(fp)
		} else {
			s.add(fp)
		}
		if len(s.seen) > capacity || len(s.order) > capacity {
			t.Fatalf("step %d: %d remembered, %d slots, cap %d", i, len(s.seen), len(s.order), capacity)
		}
		held := map[string]int{}
		for _, v := range s.order {
			if v != "" {
				held[v]++
			}
		}
		for fp, n := range held {
			if n != 1 {
				t.Fatalf("step %d: %q is in %d slots", i, fp, n)
			}
			if _, ok := s.seen[fp]; !ok {
				t.Fatalf("step %d: %q is in a slot but not remembered", i, fp)
			}
		}
		for fp := range s.seen {
			if held[fp] != 1 {
				t.Fatalf("step %d: %q is remembered but held in %d slots", i, fp, held[fp])
			}
		}
	}
}
