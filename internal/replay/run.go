package replay

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/abijit2626/ambit/internal/collector"
	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
)

// replayKey keys the fingerprint digests. It is a constant on purpose: determinism is
// worth more than secrecy here, and a replay must never read or create the production
// key. It is not a secret and protects nothing, which is why the one place digests do
// surface in a report, the domain digests inside taint labels, is acceptable: they are
// reproducible by anyone holding the input.
var replayKey = []byte("ambit-replay-fixed-key-not-a-secret")

// Options configure a run.
type Options struct {
	// Config is the base collector configuration. Per-scenario overrides apply on top.
	Config config.Config
}

// DefaultConfig is the base configuration for a replay: no filesystem side effects,
// no sampling, and a fixed home directory so zone classification does not depend on
// the machine running the replay.
func DefaultConfig() config.Config {
	cfg := config.Default()
	cfg.Home = "/home/dev"
	cfg.EndpointID = "ep_replay"
	cfg.UserID = "u_replay"
	cfg.OrgID = "o_replay"
	cfg.SampleRate = 0
	return cfg
}

// StepResult is what one step produced.
type StepResult struct {
	N    int        `json:"n"`
	Line int        `json:"line"`
	Kind event.Kind `json:"kind,omitempty"`
	// Produced is false when the collector modelled no event for this hook, which for
	// a corpus usually means a misspelled hook_event_name.
	Produced bool `json:"produced"`
	// Crossed reports whether the event reached the SIEM sink.
	Crossed bool `json:"crossed"`
	// Edges is the number of provenance edges on the event.
	Edges          int     `json:"edges,omitempty"`
	EdgeClass      string  `json:"edge_class,omitempty"`
	EdgeConfidence float64 `json:"edge_confidence,omitempty"`
	// EdgeFrom is the step the strongest edge points at; 0 if none or unresolved.
	EdgeFrom int `json:"edge_from,omitempty"`
	// R2 is the session's cumulative Rule-of-Two bits after the event, a subset of "ABC".
	R2    string   `json:"r2"`
	Taint []string `json:"taint,omitempty"`
	// Decision and Rule are the gate's session-scoped shadow verdict; TurnDecision is the
	// same action judged under per-prompt-turn scoping. Empty means no verdict.
	Decision     event.Decision `json:"decision,omitempty"`
	Rule         string         `json:"rule,omitempty"`
	TurnDecision event.Decision `json:"turn_decision,omitempty"`
	// Hostile is the step's ground truth, if annotated.
	Hostile *bool `json:"hostile,omitempty"`
	// Failures are assertions that did not hold.
	Failures []string `json:"failures,omitempty"`
}

// SessionR2 records how deep into a session each Rule-of-Two bit appeared.
type SessionR2 struct {
	SessionID string `json:"session_id"`
	// ToolCalls is how many tool calls the session made in total.
	ToolCalls int `json:"tool_calls"`
	// First* are the 1-based tool call at which each bit was first set; 0 if never.
	FirstA int `json:"first_a"`
	FirstB int `json:"first_b"`
	FirstC int `json:"first_c"`
	// FirstAll is the call at which all three were set; 0 if never.
	FirstAll int `json:"first_all"`

	seen map[string]bool
}

// Result is the outcome of replaying one scenario.
type Result struct {
	Scenario Header       `json:"scenario"`
	Path     string       `json:"path"`
	Steps    []StepResult `json:"steps"`
	Sessions []SessionR2  `json:"sessions"`
	// Stats is not serialized: Summary carries the aggregate, and the per-scenario
	// copy would only make two runs harder to diff.
	Stats collector.Stats `json:"-"`
}

// Failed reports whether any assertion failed.
func (r *Result) Failed() bool {
	for _, s := range r.Steps {
		if len(s.Failures) > 0 {
			return true
		}
	}
	return false
}

// capture is an in-memory sink. Collector sinks take whatever the collector hands
// them; for the spool that is the rich *event.Event, so no JSON round trip is needed.
type capture struct{ items []any }

func (c *capture) Write(v any) bool { c.items = append(c.items, v); return true }

// Run replays one scenario through a fresh collector. Fresh, so nothing carries over
// between scenarios: a session id reused across files must not inherit Rule-of-Two
// bits or provenance from another file, or one scenario's result would depend on which
// others ran before it.
func Run(sc *Scenario, opts Options) *Result {
	cfg := opts.Config
	applyOverrides(&cfg, sc.Config)
	cfg.SampleRate = 0 // a sampled remainder is random; a replay must not be

	events, traj := &capture{}, &capture{}
	coll := collector.New(collector.Options{
		Config:         cfg,
		EventsSink:     events,
		TrajectorySink: traj,
		Extractor:      features.New(replayKey),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:        "replay",
	})

	res := &Result{Scenario: sc.Header, Path: sc.Path}
	stepOfEvent := map[string]int{}
	sessions := map[string]*SessionR2{}
	var sessionOrder []string

	for i := range sc.Steps {
		st := &sc.Steps[i]
		beforeTraj, beforeEvents := len(traj.items), len(events.items)

		p := st.Payload
		coll.Handle(&p)

		sr := StepResult{N: st.N, Line: st.Line, Hostile: st.Hostile}
		if len(traj.items) > beforeTraj {
			e, _ := traj.items[len(traj.items)-1].(*event.Event)
			if e != nil {
				fillFromEvent(&sr, e, stepOfEvent, st.N)
				stepOfEvent[e.EventID] = st.N
				trackSession(sessions, &sessionOrder, e)
			}
		}
		sr.Crossed = len(events.items) > beforeEvents

		sr.Failures = check(st, &sr)
		res.Steps = append(res.Steps, sr)
	}

	for _, id := range sessionOrder {
		res.Sessions = append(res.Sessions, *sessions[id])
	}
	res.Stats = coll.Stats()
	return res
}

func applyOverrides(cfg *config.Config, o *ConfigOverrides) {
	if o == nil {
		return
	}
	if o.Home != "" {
		cfg.Home = o.Home
	}
	if o.TrustedRepoPaths != nil {
		cfg.TrustedRepoPaths = o.TrustedRepoPaths
	}
	if o.TrustedMCPServers != nil {
		cfg.TrustedMCPServers = o.TrustedMCPServers
	}
	if o.TrustedContentDomains != nil {
		cfg.TrustedContentDomains = o.TrustedContentDomains
	}
	if o.ExtraUntrustedPaths != nil {
		cfg.ExtraUntrustedPaths = o.ExtraUntrustedPaths
	}
}

func fillFromEvent(sr *StepResult, e *event.Event, stepOfEvent map[string]int, self int) {
	sr.Produced = true
	sr.Kind = e.Kind
	sr.R2 = bits(e.R2)
	sr.Taint = e.Provenance.Taint
	sr.Decision = e.Policy.Decision
	if len(e.Policy.RuleIDs) > 0 {
		sr.Rule = e.Policy.RuleIDs[0]
	}
	for _, alt := range e.Policy.Alternatives {
		if alt.Scoping == event.ScopingTurn {
			sr.TurnDecision = alt.Decision
		}
	}
	sr.Edges = len(e.Provenance.Edges)
	if sr.Edges > 0 {
		// The collector sorts strongest first, and the flattened event relies on that.
		top := e.Provenance.Edges[0]
		sr.EdgeClass = top.MatchClass
		sr.EdgeConfidence = top.Confidence
		sr.EdgeFrom = stepOfEvent[top.FromEvent]
	}
}

func bits(r event.R2) string {
	var b strings.Builder
	if r.A {
		b.WriteByte('A')
	}
	if r.B {
		b.WriteByte('B')
	}
	if r.C {
		b.WriteByte('C')
	}
	return b.String()
}

func trackSession(m map[string]*SessionR2, order *[]string, e *event.Event) {
	id := e.Session.SessionID
	s, ok := m[id]
	if !ok {
		s = &SessionR2{SessionID: id, seen: map[string]bool{}}
		m[id] = s
		*order = append(*order, id)
	}
	if e.Kind != event.KindToolPre && e.Kind != event.KindToolPost {
		return
	}
	// A call is counted once, by tool_use_id: its PreToolUse and PostToolUse are one call.
	// A PostToolUse whose id was never seen at a Pre is its own call, which is how a
	// hand-written trajectory that records only a result is still counted correctly.
	// A bit can flip on the Post of a call whose Pre was already counted, so depth is
	// the number of calls started so far, not events seen.
	callID := ""
	if e.Tool != nil {
		callID = e.Tool.UseID
	}
	if callID == "" || !s.seen[callID] {
		s.ToolCalls++
		if callID != "" {
			s.seen[callID] = true
		}
	}
	at := s.ToolCalls
	if e.R2.A && s.FirstA == 0 {
		s.FirstA = at
	}
	if e.R2.B && s.FirstB == 0 {
		s.FirstB = at
	}
	if e.R2.C && s.FirstC == 0 {
		s.FirstC = at
	}
	if e.R2.A && e.R2.B && e.R2.C && s.FirstAll == 0 {
		s.FirstAll = at
	}
}

// check evaluates a step's assertions and returns the ones that failed.
func check(st *Step, sr *StepResult) []string {
	ex := st.Expect
	if ex == nil {
		return nil
	}
	var f []string
	fail := func(format string, a ...any) { f = append(f, fmt.Sprintf(format, a...)) }

	if !sr.Produced {
		// Every assertion is about an event. Reporting each one as a separate failure
		// would bury the cause, which is almost always a misspelled hook name.
		return []string{fmt.Sprintf("no event was produced for hook %q, so nothing could be asserted", st.Payload.HookEventName)}
	}
	if ex.Edge != nil && *ex.Edge != (sr.Edges > 0) {
		if *ex.Edge {
			fail("expected a provenance edge, got none")
		} else {
			fail("expected no provenance edge, got %d (strongest %s at %.2f)", sr.Edges, sr.EdgeClass, sr.EdgeConfidence)
		}
	}
	if ex.EdgeClass != "" && sr.EdgeClass != ex.EdgeClass {
		fail("expected strongest edge class %q, got %q", ex.EdgeClass, sr.EdgeClass)
	}
	if ex.EdgeFrom != 0 && sr.EdgeFrom != ex.EdgeFrom {
		fail("expected the strongest edge to point at step %d, got step %d", ex.EdgeFrom, sr.EdgeFrom)
	}
	if ex.Crosses != nil && *ex.Crosses != sr.Crossed {
		fail("expected crosses=%v, got %v", *ex.Crosses, sr.Crossed)
	}
	if ex.R2 != nil && *ex.R2 != sr.R2 {
		fail("expected Rule-of-Two bits %q, got %q", *ex.R2, sr.R2)
	}
	if ex.Taint != "" {
		found := false
		for _, t := range sr.Taint {
			if strings.HasPrefix(t, ex.Taint) {
				found = true
			}
		}
		if !found {
			fail("expected a taint label with prefix %q, got %v", ex.Taint, sr.Taint)
		}
	}
	if ex.Decision != "" && ex.Decision != decisionName(sr.Decision) {
		fail("expected session verdict %q, got %q", ex.Decision, decisionName(sr.Decision))
	}
	if ex.Rule != "" && ex.Rule != sr.Rule {
		fail("expected verdict rule %q, got %q", ex.Rule, sr.Rule)
	}
	if ex.TurnDecision != "" && ex.TurnDecision != decisionName(sr.TurnDecision) {
		fail("expected turn verdict %q, got %q", ex.TurnDecision, decisionName(sr.TurnDecision))
	}
	return f
}

// decisionName spells the empty decision "none", so an assertion can say "nothing fired"
// explicitly rather than by leaving the field out, which asserts nothing.
func decisionName(d event.Decision) string {
	if d == event.DecisionNone {
		return "none"
	}
	return string(d)
}

// sortedKeys returns a map's keys in order, for stable output.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
