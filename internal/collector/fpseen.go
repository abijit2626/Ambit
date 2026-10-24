package collector

// fpSet remembers which notable fingerprints a session has already sighted, so a session handling the same
// content over and over sends one fp_sighting event rather than one per tool result. Rule 100281 needs
// the same fingerprint in two different sessions; repeats inside one session add noise and cost, and once
// another session has sighted the fingerprint each repeat pairs with it and raises 100281 again, which
// pushes 100282 over its threshold with only two sessions involved (20 alerts from 21 events).
//
// The set is bounded. When it is full the oldest fingerprint (by first send, not by last use) is
// forgotten, so a fingerprint can be sent again after enough other fingerprints have passed. That costs
// a repeat sighting and never a missed one: forgetting can only make add report true when it would have
// said false. A capacity below 1 remembers nothing, so every call reports true.
type fpSet struct {
	cap   int
	seen  map[string]struct{}
	order []string // insertion order, used as a ring once len(order) == cap
	next  int      // slot of the oldest entry once the ring is full
}

func newFPSet(capacity int) *fpSet {
	return &fpSet{cap: capacity, seen: map[string]struct{}{}}
}

// forget takes fp back out, so the next add reports it as new again. It is for a sighting that never
// reached the SIEM: the session should not count as having sent what the sink refused. The slot is
// emptied rather than removed, so the ring keeps its order and a later eviction cannot delete a
// fingerprint that was added again.
func (s *fpSet) forget(fp string) {
	if _, ok := s.seen[fp]; !ok {
		return
	}
	delete(s.seen, fp)
	for i, v := range s.order {
		if v == fp {
			s.order[i] = ""
			return
		}
	}
}

// add records fp and reports whether the session had not sent it before.
func (s *fpSet) add(fp string) bool {
	if s.cap < 1 {
		return true
	}
	if _, ok := s.seen[fp]; ok {
		return false
	}
	if len(s.order) < s.cap {
		s.order = append(s.order, fp)
	} else {
		if old := s.order[s.next]; old != "" { // "" is a slot forget() emptied
			delete(s.seen, old)
		}
		s.order[s.next] = fp
		s.next = (s.next + 1) % s.cap
	}
	s.seen[fp] = struct{}{}
	return true
}
