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

var replayKey = []byte("ambit-replay-fixed-key-not-a-secret")

type Options struct {
	Config config.Config
}

func DefaultConfig() config.Config {
	cfg := config.Default()
	cfg.Home = "/home/dev"
	cfg.EndpointID = "ep_replay"
	cfg.UserID = "u_replay"
	cfg.OrgID = "o_replay"
	cfg.SampleRate = 0
	return cfg
}

type StepResult struct {
	N    int        `json:"n"`
	Line int        `json:"line"`
	Kind event.Kind `json:"kind,omitempty"`

	Produced bool `json:"produced"`

	Crossed bool `json:"crossed"`

	Edges          int     `json:"edges,omitempty"`
	EdgeClass      string  `json:"edge_class,omitempty"`
	EdgeConfidence float64 `json:"edge_confidence,omitempty"`

	EdgeFrom int `json:"edge_from,omitempty"`

	R2    string   `json:"r2"`
	Taint []string `json:"taint,omitempty"`

	Decision     event.Decision `json:"decision,omitempty"`
	Rule         string         `json:"rule,omitempty"`
	TurnDecision event.Decision `json:"turn_decision,omitempty"`

	Exfil      int    `json:"exfil,omitempty"`
	ExfilClass string `json:"exfil_class,omitempty"`
	ExfilFrom  int    `json:"exfil_from,omitempty"`

	Hostile *bool `json:"hostile,omitempty"`

	Failures []string `json:"failures,omitempty"`
}

type SessionR2 struct {
	SessionID string `json:"session_id"`

	ToolCalls int `json:"tool_calls"`

	FirstA int `json:"first_a"`
	FirstB int `json:"first_b"`
	FirstC int `json:"first_c"`

	FirstAll int `json:"first_all"`

	seen map[string]bool
}

type Result struct {
	Scenario Header       `json:"scenario"`
	Path     string       `json:"path"`
	Steps    []StepResult `json:"steps"`
	Sessions []SessionR2  `json:"sessions"`

	Stats collector.Stats `json:"-"`
}

func (r *Result) Failed() bool {
	for _, s := range r.Steps {
		if len(s.Failures) > 0 {
			return true
		}
	}
	return false
}

type capture struct{ items []any }

func (c *capture) Write(v any) bool { c.items = append(c.items, v); return true }

func Run(sc *Scenario, opts Options) *Result {
	cfg := opts.Config
	applyOverrides(&cfg, sc.Config)
	cfg.SampleRate = 0

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
	if o.MCPToolLabels != nil {
		cfg.MCPToolLabels = o.MCPToolLabels
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
	if sr.Exfil = len(e.Provenance.Exfil); sr.Exfil > 0 {
		top := e.Provenance.Exfil[0]
		sr.ExfilClass = top.MatchClass
		sr.ExfilFrom = stepOfEvent[top.FromEvent]
	}
	sr.Edges = len(e.Provenance.Edges)
	if sr.Edges > 0 {

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

func check(st *Step, sr *StepResult) []string {
	ex := st.Expect
	if ex == nil {
		return nil
	}
	var f []string
	fail := func(format string, a ...any) { f = append(f, fmt.Sprintf(format, a...)) }

	if !sr.Produced {

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
	if ex.Exfil != nil && *ex.Exfil != (sr.Exfil > 0) {
		if *ex.Exfil {
			fail("expected a sensitive-data edge, got none")
		} else {
			fail("expected no sensitive-data edge, got %d (strongest %s)", sr.Exfil, sr.ExfilClass)
		}
	}
	if ex.ExfilClass != "" && ex.ExfilClass != sr.ExfilClass {
		fail("expected sensitive-data edge class %q, got %q", ex.ExfilClass, sr.ExfilClass)
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

func decisionName(d event.Decision) string {
	if d == event.DecisionNone {
		return "none"
	}
	return string(d)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
