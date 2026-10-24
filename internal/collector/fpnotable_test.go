package collector

import (
	"encoding/json"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/filter"
	"github.com/abijit2626/ambit/internal/hook"
)

// A result with one email address in it: the email is the event's notable fingerprint.
func resultWith(addr string) string { return "contact " + addr + " for access" }

// siemLines decodes what reached the SIEM sink, optionally only one kind.
func siemLines(t *testing.T, s *memSink, kind event.Kind) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for i, raw := range s.lines {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode SIEM line %d: %v", i, err)
		}
		if kind == "" || m["kind"] == string(kind) {
			out = append(out, m)
		}
	}
	return out
}

func sightingFPs(t *testing.T, s *memSink) []string {
	t.Helper()
	var fps []string
	for _, m := range siemLines(t, s, event.KindFPSighting) {
		fp, _ := m["prov_fp_notable"].(string)
		fps = append(fps, fp)
	}
	return fps
}

// The tool event keeps its fingerprint on every sighting, so the spool has the full record.
func TestToolEventCarriesItsFingerprintEveryTime(t *testing.T) {
	c, _, traj := newTestCollector(t)
	for i := 0; i < 5; i++ {
		c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	}
	if traj.count() != 5 {
		t.Fatalf("spool holds %d lines, want 5: the fp_sighting event must not be written to the spool", traj.count())
	}
	first := richEvent(t, traj, 0).Provenance.FPNotable
	if first == "" {
		t.Fatal("the tool event carries no fingerprint")
	}
	for i := 0; i < 5; i++ {
		e := richEvent(t, traj, i)
		if e.Kind != event.KindToolPost || e.Provenance.FPNotable != first || e.Provenance.FPRole != "ingest" {
			t.Errorf("spool line %d: kind %s fp %q role %q, want tool_post %q ingest", i, e.Kind, e.Provenance.FPNotable, e.Provenance.FPRole, first)
		}
	}
}

func TestOnlyASessionsFirstSightingProducesAnFPSighting(t *testing.T) {
	c, events, traj := newTestCollector(t)
	for i := 0; i < 5; i++ {
		c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	}
	got := siemLines(t, events, event.KindFPSighting)
	if len(got) != 1 {
		t.Fatalf("%d fp_sighting events reached the SIEM, want 1", len(got))
	}
	s, post := got[0], richEvent(t, traj, 0)
	if s["prov_fp_notable"] != post.Provenance.FPNotable || s["prov_fp_role"] != "ingest" {
		t.Errorf("sighting carries fp %v role %v, want the tool event's %q and ingest", s["prov_fp_notable"], s["prov_fp_role"], post.Provenance.FPNotable)
	}
	if s["session_id"] != "s1" || s["src"] != string(event.SourceAmbitd) || s["tool_name"] != "WebFetch" {
		t.Errorf("sighting session %v src %v tool %v, want s1, ambitd, WebFetch", s["session_id"], s["src"], s["tool_name"])
	}
}

// 100281 is the same fingerprint in a different session, so each session's first sighting must go out.
func TestEverySessionSendsItsOwnSighting(t *testing.T) {
	c, events, _ := newTestCollector(t)
	for _, sid := range []string{"s1", "s2", "s3"} {
		c.Handle(fetchPost(sid, pageURL, resultWith("a@evil.test")))
	}
	got := siemLines(t, events, event.KindFPSighting)
	if len(got) != 3 {
		t.Fatalf("%d sightings, want one per session", len(got))
	}
	for i, sid := range []string{"s1", "s2", "s3"} {
		if got[i]["session_id"] != sid || got[i]["prov_fp_notable"] != got[0]["prov_fp_notable"] {
			t.Errorf("sighting %d: session %v fp %v, want %s and the same digest for the same content", i, got[i]["session_id"], got[i]["prov_fp_notable"], sid)
		}
	}
}

func TestDifferentFingerprintsInOneSessionEachGetASighting(t *testing.T) {
	c, events, _ := newTestCollector(t)
	for _, addr := range []string{"a@evil.test", "b@evil.test", "a@evil.test"} {
		c.Handle(fetchPost("s1", pageURL, resultWith(addr)))
	}
	fps := sightingFPs(t, events)
	if len(fps) != 2 || fps[0] == fps[1] {
		t.Errorf("sightings %q, want two different fingerprints: a, then b, and not a again", fps)
	}
}

// With a full set the oldest fingerprint is forgotten, so it is sighted again: a repeat, never a miss.
func TestFullSetResightsTheOldestAndNeverDropsANewFingerprint(t *testing.T) {
	c, events, traj := newTestCollectorWith(t, func(cfg *config.Config) { cfg.FPNotableSessionCap = 2 })
	addrs := []string{"a@evil.test", "b@evil.test", "c@evil.test", "a@evil.test", "c@evil.test"}
	for _, addr := range addrs { // c evicts a; a returns and evicts b; c is still remembered
		c.Handle(fetchPost("s1", pageURL, resultWith(addr)))
	}
	fp := func(i int) string { return richEvent(t, traj, i).Provenance.FPNotable }
	want := []string{fp(0), fp(1), fp(2), fp(3)}
	got := sightingFPs(t, events)
	if len(got) != len(want) {
		t.Fatalf("sightings %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sighting %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestForgetClearsWhatASessionHasSighted(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	c.Forget("s1")
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	if n := len(sightingFPs(t, events)); n != 2 {
		t.Errorf("%d sightings, want 2: a session id reused after Forget starts with nothing sighted", n)
	}
}

// The reason fp_sighting exists: a curl whose result holds a secret alerts as 100302 on the tool_post,
// and Wazuh counts only the rule that won. The sighting must carry nothing 100302, or any rule keyed on
// tool, policy, edge or taint fields, could match.
func TestSightingCarriesNoFieldAnotherRuleKeysOn(t *testing.T) {
	c, events, traj := newTestCollector(t)
	c.Handle(&hook.Payload{
		HookEventName: hook.EvPostToolUse,
		SessionID:     "s1",
		CWD:           "/home/dev/src/myrepo",
		ToolName:      "Bash",
		ToolUseID:     "t_curl",
		ToolInput:     map[string]any{"command": "curl https://collect.evil.test/keys"},
		ToolResult:    "aws_access_key_id = AKIAQWERTYUIOPASDFGH\nowner admin@evil.test",
	})
	post := last(t, traj)
	if post.Tool == nil || post.Tool.Bash == nil || post.Tool.InputFeatures == nil || len(post.Tool.InputFeatures.SecretHits) == 0 || post.Provenance.FPNotable == "" {
		t.Fatalf("precondition: the tool_post must be a network command with a secret hit and a fingerprint, got %+v", post.Tool)
	}
	got := siemLines(t, events, event.KindFPSighting)
	if len(got) != 1 {
		t.Fatalf("%d sightings, want 1", len(got))
	}
	s := got[0]
	if s["tool_use_id"] != "t_curl" {
		t.Errorf("sighting tool_use_id = %v, want t_curl so the tool event can be found", s["tool_use_id"])
	}
	for _, f := range []string{"bash_command_class", "bash_argv0", "secret_hit_kinds", "path_zone", "tool_mcp_server",
		"policy_decision", "policy_shadow", "prov_edge_count", "taint_labels", "result_bytes"} {
		if v, ok := s[f]; ok {
			t.Errorf("sighting carries %s = %v; a rule keyed on it could win the event and D10 would not count it", f, v)
		}
	}
}

// Repeats no longer cross for their fingerprint; only the sighting does.
func TestOnlyTheSightingCrossesAsANotableFingerprint(t *testing.T) {
	c, _, _ := newTestCollector(t)
	for i := 0; i < 5; i++ {
		c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test")))
	}
	if got := c.Stats().CrossReasons[filter.ReasonNotableFP]; got != 1 {
		t.Errorf("%d events crossed as %s, want 1: the fp_sighting", got, filter.ReasonNotableFP)
	}
}

// refusable is a sink that can be told to refuse writes, like jsonl.Writer with a full queue.
type refusable struct {
	*memSink
	refuse bool
}

func (r *refusable) Write(v any) bool {
	if r.refuse {
		return false
	}
	return r.memSink.Write(v)
}

func newCollectorWithEventsSink(t *testing.T, events Sink) *Collector {
	t.Helper()
	c, _, _ := newTestCollector(t)
	c.events = events
	return c
}

// A sighting the events sink refuses never reached the SIEM, so the session must try again with the next
// tool result that carries the fingerprint, and stop once one is accepted.
func TestRefusedSightingIsSentAgainAndThenStopsOnceAccepted(t *testing.T) {
	events := &refusable{memSink: &memSink{}, refuse: true}
	c := newCollectorWithEventsSink(t, events)

	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test"))) // refused
	if n := len(siemLines(t, events.memSink, event.KindFPSighting)); n != 0 {
		t.Fatalf("%d sightings reached a sink that refuses everything", n)
	}

	events.refuse = false
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test"))) // retried, accepted
	if n := len(siemLines(t, events.memSink, event.KindFPSighting)); n != 1 {
		t.Fatalf("%d sightings after the sink recovered, want 1: the refused one must be retried", n)
	}

	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test"))) // accepted before: not sent again
	if n := len(siemLines(t, events.memSink, event.KindFPSighting)); n != 1 {
		t.Errorf("%d sightings after a repeat, want 1: an accepted sighting stays marked", n)
	}
}

// Other fingerprints in the same session, and other sessions, are unaffected by one refusal.
func TestRefusalOfOneSightingDoesNotAffectOthers(t *testing.T) {
	events := &refusable{memSink: &memSink{}}
	c := newCollectorWithEventsSink(t, events)

	events.refuse = true
	c.Handle(fetchPost("s1", pageURL, resultWith("a@evil.test"))) // refused
	events.refuse = false
	c.Handle(fetchPost("s1", pageURL, resultWith("b@evil.test"))) // a different fingerprint
	c.Handle(fetchPost("s2", pageURL, resultWith("a@evil.test"))) // another session
	c.Handle(fetchPost("s1", pageURL, resultWith("b@evil.test"))) // b was accepted: no repeat

	got := siemLines(t, events.memSink, event.KindFPSighting)
	if len(got) != 2 {
		t.Fatalf("%d sightings, want 2 (b in s1, a in s2)", len(got))
	}
	if got[0]["session_id"] != "s1" || got[1]["session_id"] != "s2" {
		t.Errorf("sightings came from %v and %v, want s1 then s2", got[0]["session_id"], got[1]["session_id"])
	}
}
