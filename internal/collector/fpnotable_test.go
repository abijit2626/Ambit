package collector

import (
	"encoding/json"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
)

// A result with one email address in it: the email is the event's notable fingerprint.
func resultWith(addr string) string { return "contact " + addr + " for access" }

func fpOf(t *testing.T, s *memSink, i int) (fp, role string) {
	t.Helper()
	e := richEvent(t, s, i)
	return e.Provenance.FPNotable, e.Provenance.FPRole
}

func TestSessionSendsAFingerprintOnlyTheFirstTime(t *testing.T) {
	c, _, traj := newTestCollector(t)
	for i := 0; i < 5; i++ {
		c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	}
	first, role := fpOf(t, traj, 0)
	if first == "" || role != "ingest" {
		t.Fatalf("first sighting carries fp %q role %q, want a fingerprint and role ingest", first, role)
	}
	for i := 1; i < 5; i++ {
		if fp, role := fpOf(t, traj, i); fp != "" || role != "" {
			t.Errorf("repeat %d in the same session carries fp %q role %q, want neither", i, fp, role)
		}
	}
}

// 100281 is the same fingerprint in a different session, so each session's first sighting must go out.
func TestEverySessionSendsItsOwnFirstSighting(t *testing.T) {
	c, _, traj := newTestCollector(t)
	for _, sid := range []string{"s1", "s2", "s3"} {
		c.Handle(fetchPost(sid, pageURL, resultWith("a@evil.test")))
	}
	var want string
	for i := 0; i < 3; i++ {
		fp, _ := fpOf(t, traj, i)
		if fp == "" {
			t.Fatalf("session %d sent no fingerprint: another session's sighting must not suppress it", i+1)
		}
		if want == "" {
			want = fp
		}
		if fp != want {
			t.Errorf("session %d sent %q, want the same digest %q for the same content", i+1, fp, want)
		}
	}
}

func TestDifferentFingerprintsInOneSessionAreEachSent(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	c.Handle(fetchPost("s1", pageURL, resultWith("b@evil.test")))
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	fa, _ := fpOf(t, traj, 0)
	fb, _ := fpOf(t, traj, 1)
	fa2, _ := fpOf(t, traj, 2)
	if fa == "" || fb == "" || fa == fb {
		t.Fatalf("want two different fingerprints, got %q and %q", fa, fb)
	}
	if fa2 != "" {
		t.Errorf("a's second sighting carries %q; b in between must not make a new again", fa2)
	}
}

// With a full set the oldest fingerprint is forgotten, so it is sent again: a repeat, never a miss.
func TestFullSetResendsTheOldestAndNeverDropsANewFingerprint(t *testing.T) {
	c, _, traj := newTestCollectorWith(t, func(cfg *config.Config) { cfg.FPNotableSessionCap = 2 })
	for _, addr := range []string{"a@evil.test", "b@evil.test", "c@evil.test"} { // c evicts a
		c.Handle(fetchPost("s1", pageURL, resultWith(addr)))
	}
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test"))) // evicted: sent again, evicts b
	c.Handle(fetchPost("s1", pageURL, resultWith("c@evil.test"))) // still remembered
	for i, wantSent := range []bool{true, true, true, true, false} {
		fp, _ := fpOf(t, traj, i)
		if (fp != "") != wantSent {
			t.Errorf("event %d: sent=%v, want %v", i, fp != "", wantSent)
		}
	}
}

func TestForgetClearsWhatASessionHasSent(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	c.Forget("s1")
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	if fp, _ := fpOf(t, traj, 1); fp == "" {
		t.Error("a session reusing an id after Forget was treated as having sent the fingerprint already")
	}
}

// What reaches the SIEM: the first sighting, carrying the fingerprint, and nothing for the repeats. Before
// this change every repeat crossed as a notable fingerprint.
func TestRepeatSightingsDoNotReachTheSIEM(t *testing.T) {
	c, events, _ := newTestCollector(t)
	for i := 0; i < 5; i++ {
		c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	}
	if events.count() != 1 {
		t.Fatalf("%d events reached the SIEM sink, want 1: the first sighting only", events.count())
	}
	var line map[string]any
	events.mu.Lock()
	err := json.Unmarshal(events.lines[0], &line)
	events.mu.Unlock()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if line["prov_fp_notable"] == nil || line["prov_fp_role"] != "ingest" {
		t.Errorf("the event that crossed carries prov_fp_notable=%v prov_fp_role=%v, want a fingerprint and ingest", line["prov_fp_notable"], line["prov_fp_role"])
	}
}
