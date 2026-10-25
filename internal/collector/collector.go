package collector

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/drift"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/filter"
	"github.com/abijit2626/ambit/internal/gate"
	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/prov"
	"github.com/abijit2626/ambit/internal/r2"
	"github.com/abijit2626/ambit/internal/redact"
)

var runtimeGOOS = runtime.GOOS

type Sink interface {
	Write(v any) bool
}

type sessionState struct {
	mu       sync.Mutex
	sequence int64
	cwd      string
	home     string
	model    string
	permMode string
	zoner    *classify.Zoner

	r2 event.R2

	turnPrompt string
	turnBits   r2.Bits

	prov *prov.Set

	sens *prov.Set

	fpSent *fpSet

	modeSent string

	started, prompted, noPromptSent bool

	// goal is the session's latest prompt, redacted, kept only while the goal-drift judge is on.
	goal string
}

// observePrompting records the parts of a session's shape that "no prompt before a tool call" needs, and
// reports whether e is the first tool call of a session that ambitd saw start and that has had no prompt.
// A SessionStart from compaction continues the session, so it changes nothing. A session ambitd did not
// see start (it began before ambitd did, or SessionStart is not hooked) is never reported.
func (s *sessionState) observePrompting(p *hook.Payload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch p.HookEventName {
	case hook.EvSessionStart:
		if p.Source != "compact" {
			s.started, s.prompted, s.noPromptSent = true, false, false
		}
	case hook.EvUserPromptSubmit:
		s.prompted = true
	case hook.EvPreToolUse:
		if s.started && !s.prompted && !s.noPromptSent {
			s.noPromptSent = true
			return true
		}
	}
	return false
}

// unsendNoPrompt undoes observePrompting's report for a session_no_prompt the events sink refused, so the
// session's next tool call tries again, unless a prompt has arrived since.
func (s *sessionState) unsendNoPrompt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noPromptSent = false
}

// takeModeChange reports the session's mode when ambitd has not yet sent it as a session_mode event:
// the first time the mode is known, and each time it changes. prev is what to restore if the send fails.
func (s *sessionState) takeModeChange() (mode, prev string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.permMode == "" || s.permMode == s.modeSent {
		return "", "", false
	}
	prev, s.modeSent = s.modeSent, s.permMode
	return s.permMode, prev, true
}

// unsendMode undoes takeModeChange for a session_mode event the events sink refused, unless a later
// change has already been sent.
func (s *sessionState) unsendMode(mode, prev string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.modeSent == mode {
		s.modeSent = prev
	}
}

// unsightFingerprint undoes firstFingerprintSighting for a sighting the events sink refused.
func (s *sessionState) unsightFingerprint(fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fpSent.forget(fp)
}

// firstFingerprintSighting reports whether this session has not yet sent fp as its notable fingerprint.
func (s *sessionState) firstFingerprintSighting(fp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fpSent.add(fp)
}

type priorBits struct {
	session, turn r2.Bits
}

func (s *sessionState) setR2Bits(newBits r2.Bits, eventID, promptID string) (event.R2, priorBits) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if promptID != "" && promptID != s.turnPrompt {
		s.turnPrompt = promptID
		s.turnBits = r2.Bits{}
	}
	prior := priorBits{
		session: r2.Bits{A: s.r2.A, B: s.r2.B, C: s.r2.C},
		turn:    s.turnBits,
	}
	s.turnBits = s.turnBits.Or(newBits)

	transitioned := (newBits.A && !s.r2.A) || (newBits.B && !s.r2.B) || (newBits.C && !s.r2.C)
	s.r2.A = s.r2.A || newBits.A
	s.r2.B = s.r2.B || newBits.B
	s.r2.C = s.r2.C || newBits.C

	out := s.r2
	out.Transition = transitioned
	if transitioned {
		s.r2.SetBy = eventID
		out.SetBy = eventID
	}
	return out, prior
}

type Collector struct {
	cfg      config.Config
	events   Sink
	traj     Sink
	filt     *filter.Filter
	ext      *features.Extractor
	red      *redact.Redactor
	log      *slog.Logger
	version  string
	hostname string

	webDomainTrust map[string]bool

	mu       sync.Mutex
	sessions map[string]*sessionState

	handled atomic.Int64
	crossed atomic.Int64
	derived atomic.Int64

	hookToolCalls   atomic.Int64
	hookToolCrossed atomic.Int64

	provIngests    atomic.Int64
	provRegistered atomic.Int64
	provSkipped    atomic.Int64
	provTruncated  atomic.Int64
	provEvicted    atomic.Int64
	provEdgeEvents atomic.Int64

	provExfilEvents atomic.Int64

	shadowDeny    atomic.Int64
	shadowAsk     atomic.Int64
	shadowAlert   atomic.Int64
	otelRecords   atomic.Int64
	otelToolCalls atomic.Int64
	otelLastSeen  atomic.Int64

	interposeReports atomic.Int64
	interposeEvents  atomic.Int64

	reasonMu     sync.Mutex
	crossReasons map[string]int64

	annMu sync.Mutex
	ann   annotationCache

	drift *drift.Scorer
}

type Options struct {
	Config         config.Config
	EventsSink     Sink
	TrajectorySink Sink
	Extractor      *features.Extractor
	Logger         *slog.Logger
	Version        string
	// Drift is the goal-drift judge; nil leaves it off.
	Drift *drift.Scorer
}

func New(opts Options) *Collector {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	fc := filter.DefaultConfig()
	fc.SampleRate = opts.Config.SampleRate
	fc.DriftThreshold = opts.Config.DriftThreshold
	fc.TrustedMCPServers = opts.Config.TrustedMCPSet()

	hostname, _ := os.Hostname()

	webDomainTrust := make(map[string]bool, len(opts.Config.TrustedContentDomains))
	for _, d := range opts.Config.TrustedContentDomains {
		if d == "" {
			continue
		}

		webDomainTrust[opts.Extractor.Digest(features.Registrable(d))] = true
	}

	return &Collector{
		cfg:            opts.Config,
		hostname:       hostname,
		events:         opts.EventsSink,
		traj:           opts.TrajectorySink,
		filt:           filter.New(fc),
		ext:            opts.Extractor,
		red:            redact.New(),
		log:            opts.Logger,
		version:        opts.Version,
		sessions:       map[string]*sessionState{},
		crossReasons:   map[string]int64{},
		webDomainTrust: webDomainTrust,
		drift:          opts.Drift,
	}
}

func (c *Collector) Handle(p *hook.Payload) {
	c.handled.Add(1)
	e, sighting, st := c.build(p)
	if e == nil {
		return
	}
	if e.Kind == event.KindToolPre || e.Kind == event.KindToolPost {
		c.hookToolCalls.Add(1)
	}

	c.emit(e)
	c.scoreDrift(st, p, e)
	c.emitModeChange(st, e)
	c.emitNoPrompt(st, p, e)
	c.emitSandboxDenial(st, p, e)
	if sighting != nil && !c.emitDerived(sighting) {
		// the events sink refused it (its queue is full): the session has not sent this fingerprint, so
		// the next tool result that carries it must try again
		st.unsightFingerprint(sighting.Provenance.FPNotable)
	}

	if p.HookEventName == hook.EvSessionEnd {
		c.Forget(p.SessionID)
	}
}

func (c *Collector) emit(e *event.Event) {
	c.traj.Write(e)

	v := c.filt.Decide(e)
	c.recordReason(v)
	if v.Cross {
		c.crossed.Add(1)
		if e.Source == event.SourceHook && (e.Kind == event.KindToolPre || e.Kind == event.KindToolPost) {
			c.hookToolCrossed.Add(1)
		}
		c.events.Write(filter.Sanitize(event.Flatten(e)))
	}
}

// emitDerived sends an event ambitd derived from one already in the spool to the SIEM only. The spool
// keeps one line per hook event; an fp_sighting can be rebuilt from it as the first tool event in a
// session carrying that fingerprint.
// It reports whether the event reached the sink, which is false only if the sink refused it. Derived
// events are counted apart from crossed, which counts handled events, so the interesting fraction
// stays a fraction of what ambitd handled.
func (c *Collector) emitDerived(e *event.Event) bool {
	v := c.filt.Decide(e)
	c.recordReason(v)
	if !v.Cross {
		return true
	}
	if !c.events.Write(filter.Sanitize(event.Flatten(e))) {
		return false
	}
	c.derived.Add(1)
	return true
}

// scoreDrift asks the goal-drift judge about a tool call that carries a provenance edge, which is where a
// value from something the agent read reaches what it does next. Asking about every tool call would cost
// a model call each and, on the prototype, flag far more benign calls (docs/03-detection.md). The score
// arrives later on the judge's goroutine; it goes to the spool, and to the SIEM when it is over
// drift_threshold.
func (c *Collector) scoreDrift(st *sessionState, p *hook.Payload, e *event.Event) {
	if c.drift == nil || e.Kind != event.KindToolPre || e.Tool == nil || len(e.Provenance.Edges) == 0 {
		return
	}
	st.mu.Lock()
	goal := st.goal
	st.mu.Unlock()
	if goal == "" {
		return
	}
	raw, err := json.Marshal(p.ToolInput)
	if err != nil {
		return
	}
	input, _ := c.red.Redact(string(raw))
	from := e
	c.drift.Submit(drift.Request{Goal: goal, Tool: p.ToolName, Input: input}, func(r drift.Result) {
		d := goalDriftScore(from, st, r)
		c.traj.Write(d)
		c.emitDerived(d)
	})
}

// goalDriftScore is the event rules 100330 and 100331 read: the judge's score for one tool call, found
// again by tool_use_id. It leaves out the provenance edge that made the call worth asking about: the tool
// event already carried it to Wazuh (rule 100283), and an edge here would let that rule take this event.
func goalDriftScore(from *event.Event, st *sessionState, r drift.Result) *event.Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	score := r.Score
	d := &event.Event{
		EventID:    newEventID(),
		TS:         now,
		IngestedAt: now,
		Source:     event.SourceAmbitd,
		SchemaV:    from.SchemaV,
		Kind:       event.KindGoalDriftScore,
		Endpoint:   from.Endpoint,
		Actor:      from.Actor,
		Agent:      from.Agent,
		Session:    from.Session,
		Tool:       &event.Tool{Name: from.Tool.Name, UseID: from.Tool.UseID},
		R2:         from.R2,
		Policy:     event.Policy{Decision: event.DecisionNone},
		Scores:     event.Scores{GoalDrift: &score, DriftScorerV: r.Scorer},
	}
	d.Session.Sequence = st.next()
	d.R2.Transition = false
	return d
}

// emitModeChange sends a session_mode event when e is the first event of its session to carry a
// permission mode, or carries a different one from the last sent. SessionStart has no mode, so for most
// sessions this is the first prompt.
func (c *Collector) emitModeChange(st *sessionState, e *event.Event) {
	mode, prev, ok := st.takeModeChange()
	if !ok {
		return
	}
	if !c.emitDerived(sessionMode(e, mode, st)) {
		st.unsendMode(mode, prev)
	}
}

// emitNoPrompt sends a session_no_prompt event for the first tool call of a session that started with
// ambitd watching and has had no prompt.
func (c *Collector) emitNoPrompt(st *sessionState, p *hook.Payload, e *event.Event) {
	if !st.observePrompting(p) {
		return
	}
	if !c.emitDerived(sessionNoPrompt(e, st)) {
		st.unsendNoPrompt()
	}
}

func (c *Collector) recordReason(v filter.Verdict) {
	key := v.Reason
	if !v.Cross {
		key = "not_interesting"
	}
	c.reasonMu.Lock()
	c.crossReasons[key]++
	c.reasonMu.Unlock()
}

// build returns the event for p, its session, and, when p is a session's first sighting of a notable
// fingerprint, the fp_sighting event that goes with it.
func (c *Collector) build(p *hook.Payload) (*event.Event, *event.Event, *sessionState) {
	kind, ok := kindFor(p.HookEventName)
	if !ok {
		return nil, nil, nil
	}
	st := c.session(p)

	now := time.Now().UTC()
	e := &event.Event{
		EventID:    newEventID(),
		TS:         now.Format(time.RFC3339Nano),
		IngestedAt: now.Format(time.RFC3339Nano),
		Source:     event.SourceHook,
		SchemaV:    event.SchemaVersion,
		Kind:       kind,
		Endpoint: event.Endpoint{
			EndpointID:    c.cfg.EndpointID,
			OS:            runtimeGOOS,
			AmbitdVersion: c.version,
		},
		Actor: event.Actor{UserID: c.cfg.UserID, OrgID: c.cfg.OrgID},
		Agent: event.Agent{
			Kind:           "claude-code",
			Model:          st.model,
			PermissionMode: st.permMode,
			CWDDigest:      c.ext.Digest(st.cwd),
		},
		Session: event.Session{
			SessionID: p.SessionID,
			PromptID:  p.PromptID,
			Sequence:  st.next(),
			AgentID:   p.AgentID,
			AgentType: p.AgentType,
		},
		R2: st.snapshotR2(),

		Policy: event.Policy{Decision: event.DecisionNone},
	}
	if c.hostname != "" {

		e.Endpoint.HostnameDigest = c.ext.Digest(c.hostname)
	}

	var sighting *event.Event
	switch kind {
	case event.KindPromptSubmit:
		c.fillPrompt(e, p, st)
	case event.KindToolPre, event.KindToolPost, event.KindToolFail, event.KindPermissionRequest, event.KindPermissionDenied:
		if c.fillTool(e, p, st) {
			sighting = fpSighting(e, st)
		}
	case event.KindInstructionsLoaded, event.KindConfigChange, event.KindFileChanged:
		c.fillConfig(e, p, st)
	}
	return e, sighting, st
}

// sessionMode is the event rule 100200 reads: the session's identity and its permission mode, with no
// tool, path or policy fields, so no tool rule can match it.
func sessionMode(from *event.Event, mode string, st *sessionState) *event.Event {
	m := &event.Event{
		EventID:    newEventID(),
		TS:         from.TS,
		IngestedAt: from.IngestedAt,
		Source:     event.SourceAmbitd,
		SchemaV:    from.SchemaV,
		Kind:       event.KindSessionMode,
		Endpoint:   from.Endpoint,
		Actor:      from.Actor,
		Agent:      from.Agent,
		Session:    event.Session{SessionID: from.Session.SessionID, PromptID: from.Session.PromptID},
		R2:         from.R2,
		Policy:     event.Policy{Decision: event.DecisionNone},
	}
	m.Agent.PermissionMode = mode
	m.Session.Sequence = st.next()
	m.R2.Transition = false
	return m
}

// sessionNoPrompt is the event rules 100206 and 100207 read: the session, its mode, and the name and
// tool_use_id of the tool call that came before any prompt. It carries no path, command or policy
// field, so no tool rule can match it.
func sessionNoPrompt(from *event.Event, st *sessionState) *event.Event {
	n := &event.Event{
		EventID:    newEventID(),
		TS:         from.TS,
		IngestedAt: from.IngestedAt,
		Source:     event.SourceAmbitd,
		SchemaV:    from.SchemaV,
		Kind:       event.KindSessionNoPrompt,
		Endpoint:   from.Endpoint,
		Actor:      from.Actor,
		Agent:      from.Agent,
		Session:    event.Session{SessionID: from.Session.SessionID, AgentID: from.Session.AgentID, AgentType: from.Session.AgentType},
		R2:         from.R2,
		Policy:     event.Policy{Decision: event.DecisionNone},
	}
	n.Session.Sequence = st.next()
	n.R2.Transition = false
	if from.Tool != nil {
		n.Tool = &event.Tool{Name: from.Tool.Name, UseID: from.Tool.UseID}
	}
	return n
}

// fpSighting is the event the D10 rules count: the identity and session of the tool event that first
// carried the fingerprint, the fingerprint itself, and tool_use_id to find that tool event again. It
// carries no tool, policy or taint fields, so no rule that keys on those can win it instead of 100280.
func fpSighting(from *event.Event, st *sessionState) *event.Event {
	s := &event.Event{
		EventID:    newEventID(),
		TS:         from.TS,
		IngestedAt: from.IngestedAt,
		Source:     event.SourceAmbitd,
		SchemaV:    from.SchemaV,
		Kind:       event.KindFPSighting,
		Endpoint:   from.Endpoint,
		Actor:      from.Actor,
		Agent:      from.Agent,
		Session:    from.Session,
		Provenance: event.Provenance{FPNotable: from.Provenance.FPNotable, FPRole: from.Provenance.FPRole},
		R2:         from.R2,
		Policy:     event.Policy{Decision: event.DecisionNone},
	}
	s.Session.Sequence = st.next()
	s.R2.Transition = false
	if from.Tool != nil {
		s.Tool = &event.Tool{Name: from.Tool.Name, UseID: from.Tool.UseID}
	}
	return s
}

func (c *Collector) fillPrompt(e *event.Event, p *hook.Payload, st *sessionState) {

	prompt := p.PromptText()
	clean, hits := c.red.Redact(prompt)

	declared := c.ext.Extract(clean)
	st.prov.Declare(declared)
	st.sens.Declare(declared)
	if c.drift != nil {
		st.mu.Lock()
		st.goal = clean
		st.mu.Unlock()
	}
	e.Prompt = &event.PromptInfo{
		Text:       clean,
		TextDigest: c.ext.Digest(prompt),
		Bytes:      len(prompt),
	}
	if len(hits) > 0 {
		c.log.Warn("secret material detected in a user prompt", "kinds", len(hits))
	}
}

// fillTool reports whether the event is the session's first sighting of its notable fingerprint.
func (c *Collector) fillTool(e *event.Event, p *hook.Payload, st *sessionState) (firstSighting bool) {
	t := &event.Tool{Name: p.ToolName, UseID: p.ToolUseID, Error: p.ToolFailure()}

	if server, tool, ok := hook.IsMCPTool(p.ToolName); ok {
		trust := ""
		if c.cfg.TrustedMCPSet()[server] {
			trust = "internal"
		}
		t.MCP = &event.MCP{Server: server, Tool: tool, Trust: trust}
		if tl, ok := c.cfg.ToolLabels(server, tool); ok {
			t.MCP.Classified = true
			t.MCP.Labels = tl.Names
		}
		if a, ok := c.annotationsFor(server, tool); ok {
			t.MCP.Annotations = a
		}
	}

	if cmd := p.Command(); cmd != "" {
		argv0, class := classify.Bash(cmd)
		t.Bash = &event.Bash{
			Argv0:        argv0,
			CommandClass: class,

			CommandDigest: c.ext.Digest(cmd),
		}
	}

	for _, path := range p.Paths() {
		t.Paths = append(t.Paths, event.PathRef{
			PathDigest: c.ext.Digest(path),
			Zone:       st.zone(path),
			Op:         opFor(p.ToolName),
		})
	}

	inputText := renderInput(p)
	cleanInput, inputHits := c.red.Redact(inputText)
	t.InputDigest = c.ext.Digest(inputText)
	t.InputFeatures = c.ext.Extract(cleanInput)
	t.InputFeatures.SecretHits = toSecretHits(inputHits)

	var payloadFeatures *event.Features
	if e.Kind == event.KindToolPre {
		cleanPayload, _ := c.red.Redact(renderPayload(p))
		payloadFeatures = c.ext.Extract(cleanPayload)
	}

	var resultFeatures *event.Features
	if resultText, ok := p.ToolOutput(); ok {
		cleanResult, resultHits := c.red.Redact(resultText)
		t.ResultDigest = c.ext.Digest(resultText)
		t.ResultBytes = len(resultText)
		resultFeatures = c.ext.Extract(cleanResult)
		t.InputFeatures.SecretHits = append(t.InputFeatures.SecretHits, toSecretHits(resultHits)...)
		// the tool event always carries its fingerprint, for the spool and for context when it crosses;
		// only a session's first sighting also produces the fp_sighting event that D10 counts
		if fp := features.NotableFingerprint(resultFeatures); fp != "" {
			e.Provenance.FPNotable = fp
			e.Provenance.FPRole = "ingest"
			firstSighting = st.firstFingerprintSighting(fp)
		}
	}

	e.Tool = t

	if e.Kind == event.KindToolPre || e.Kind == event.KindToolPost {
		bits := r2.ClassifyTool(r2.ToolInput{
			ToolName:       t.Name,
			Paths:          t.Paths,
			Bash:           t.Bash,
			MCP:            t.MCP,
			SecretHitCount: len(t.InputFeatures.SecretHits),
			WebUntrusted:   c.webUntrusted(t.Name, t.InputFeatures),
		})
		var prior priorBits
		e.R2, prior = st.setR2Bits(bits, e.EventID, e.Session.PromptID)
		c.fillProvenance(e, t, st, bits, resultFeatures, payloadFeatures)
		if e.Kind == event.KindToolPre {
			c.shadowGate(e, t, bits, prior)
		}
	}
	return firstSighting
}

func (c *Collector) shadowGate(e *event.Event, t *event.Tool, bits r2.Bits, prior priorBits) {
	start := time.Now()
	action := gate.ActionFrom(t, bits)
	v := gate.Evaluate(prior.session, action)
	turn := gate.Evaluate(prior.turn, action)
	elapsed := time.Since(start)

	if v.Fired() {
		e.Policy = event.Policy{
			Decision:      v.Decision,
			Reason:        v.Reason,
			RuleIDs:       []string{v.RuleID},
			BundleVersion: gate.BundleVersion,
			LatencyUS:     elapsed.Microseconds(),
			Shadow:        true,
		}
		c.countVerdict(v.Decision)
	}
	e.Policy.Alternatives = []event.ScopedVerdict{{
		Scoping: event.ScopingTurn, Decision: turn.Decision, RuleID: turn.RuleID,
	}}
}

func (c *Collector) countVerdict(d event.Decision) {
	switch d {
	case event.DecisionDeny:
		c.shadowDeny.Add(1)
	case event.DecisionAsk:
		c.shadowAsk.Add(1)
	case event.DecisionAllowAlert:
		c.shadowAlert.Add(1)
	}
}

func (c *Collector) fillProvenance(e *event.Event, t *event.Tool, st *sessionState, bits r2.Bits, result, payload *event.Features) {
	if bits.A {

		for _, label := range c.taintLabels(t) {
			if st.prov.AddTaint(label) {
				e.Provenance.Taint = append(e.Provenance.Taint, label)
			}
		}
	}

	switch e.Kind {
	case event.KindToolPre:
		if edges := st.prov.Match(t.InputFeatures); len(edges) > 0 {
			e.Provenance.Edges = edges
			e.Provenance.IngestRefs = prov.Refs(edges)
			c.provEdgeEvents.Add(1)
		}

		if bits.C {
			if exfil := st.sens.Match(payload); len(exfil) > 0 {
				e.Provenance.Exfil = exfil
				c.provExfilEvents.Add(1)
			}
		}
	case event.KindToolPost:

		if bits.A && result != nil {
			res := st.prov.Ingest(e.EventID, result, t.InputFeatures)
			if res.Stored > 0 {
				c.provIngests.Add(1)
			}
			c.provRegistered.Add(int64(res.Stored))
			c.provSkipped.Add(int64(res.Skipped))
			c.provTruncated.Add(int64(res.Truncated))
			c.provEvicted.Add(int64(res.Evicted))
		}

		if bits.B && result != nil {
			res := st.sens.Ingest(e.EventID, result, t.InputFeatures)
			c.provTruncated.Add(int64(res.Truncated))
			c.provEvicted.Add(int64(res.Evicted))
		}
	}
}

const maxTaintLabelsPerEvent = 4

func (c *Collector) taintLabels(t *event.Tool) []string {
	var out []string
	if t.MCP != nil && mcpUntrusted(t.MCP) {
		out = append(out, "mcp:"+t.MCP.Server)
	}
	if t.Name == "WebFetch" || t.Name == "WebSearch" {
		n := 0
		if t.InputFeatures != nil {
			for _, d := range t.InputFeatures.Domains {
				if c.webDomainTrust[d] || n >= maxTaintLabelsPerEvent {
					continue
				}
				out = append(out, "web:"+d)
				n++
			}
		}
		if n == 0 {

			out = append(out, "web")
		}
	}
	if t.Bash != nil && classify.IsNetworkClass(t.Bash.CommandClass) {
		out = append(out, "bash:network")
	}
	for _, p := range t.Paths {
		if p.Zone == event.ZoneUntrusted && p.Op == "read" {
			out = append(out, "file:untrusted")
			break
		}
	}
	if len(out) > maxTaintLabelsPerEvent {
		out = out[:maxTaintLabelsPerEvent]
	}
	return out
}

func mcpUntrusted(m *event.MCP) bool {
	if m.Classified {
		for _, l := range m.Labels {
			if l == config.LabelUntrusted {
				return true
			}
		}
		return false
	}
	return m.Trust != "internal"
}

func (c *Collector) webUntrusted(toolName string, f *event.Features) bool {
	if toolName != "WebFetch" && toolName != "WebSearch" {
		return false
	}
	if f == nil || len(f.Domains) == 0 {
		return true
	}
	for _, d := range f.Domains {
		if !c.webDomainTrust[d] {
			return true
		}
	}
	return false
}

func (c *Collector) fillConfig(e *event.Event, p *hook.Payload, st *sessionState) {
	path := p.FilePath
	ci := &event.ConfigInfo{
		Source:     p.ConfigSource,
		LoadReason: p.LoadReason,
		ChangeType: p.ChangeType,
	}
	if path != "" {
		ci.PathDigest = c.ext.Digest(path)
		ci.Zone = st.zone(path)

		ci.Trusted = c.isTrustedRepoPath(path) && ci.Zone != event.ZoneUntrusted
	}
	e.Config = ci

	if e.Kind == event.KindInstructionsLoaded {
		bits := r2.ClassifyInstructionsLoaded(ci.Trusted)
		e.R2, _ = st.setR2Bits(bits, e.EventID, e.Session.PromptID)

		if bits.A && st.prov.AddTaint("instructions:untrusted") {
			e.Provenance.Taint = append(e.Provenance.Taint, "instructions:untrusted")
		}
	}
}

func (c *Collector) isTrustedRepoPath(path string) bool {
	for _, trusted := range c.cfg.TrustedRepoPaths {
		if classify.PathWithin(path, trusted) {
			return true
		}
	}
	return false
}

func (c *Collector) session(p *hook.Payload) *sessionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.sessions[p.SessionID]
	if !ok {
		home := c.homeFor(p, c.cfg.Home)
		st = &sessionState{
			cwd:      p.CWD,
			home:     home,
			zoner:    classify.NewZoner(home, p.CWD, c.cfg.ExtraUntrustedPaths),
			model:    p.Model,
			permMode: p.PermissionMode,
			prov:     prov.New(prov.Options{CommonDomains: c.webDomainTrust}),
			fpSent:   newFPSet(c.cfg.FPNotableSessionCap),

			sens: prov.New(prov.Options{CommonDomains: c.webDomainTrust, Exclude: map[string]bool{prov.ClassDomain: true}}),
		}
		c.sessions[p.SessionID] = st
	}

	st.mu.Lock()
	if p.PermissionMode != "" {
		st.permMode = p.PermissionMode
	}
	if p.Model != "" {
		st.model = p.Model
	}
	home := c.homeFor(p, st.home)
	if (p.CWD != "" && p.CWD != st.cwd) || home != st.home {

		if p.CWD != "" {
			st.cwd = p.CWD
		}
		st.home = home
		st.zoner = classify.NewZoner(home, st.cwd, c.cfg.ExtraUntrustedPaths)
	}
	st.mu.Unlock()
	return st
}

func (c *Collector) homeFor(p *hook.Payload, current string) string {
	if !c.cfg.HomeIsDetected() {
		return c.cfg.Home
	}
	if h := homeFromTranscript(p.TranscriptPath); h != "" {
		return h
	}
	return current
}

func homeFromTranscript(tp string) string {
	s := strings.ReplaceAll(tp, `\`, "/")
	i := strings.Index(s, "/.claude/projects/")
	if i <= 0 {
		return ""
	}
	return s[:i]
}

func (c *Collector) Forget(sessionID string) {
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()
}

type Stats struct {
	Handled          int64
	Crossed          int64
	Derived          int64
	HookToolCalls    int64
	HookToolCrossed  int64
	Sessions         int
	CrossReasons     map[string]int64
	InterposeReports int64
	InterposeEvents  int64

	Provenance ProvStats

	Shadow ShadowStats
}

type ShadowStats struct {
	Deny       int64
	Ask        int64
	AllowAlert int64
}

type ProvStats struct {
	Ingests    int64
	Registered int64
	Skipped    int64
	Truncated  int64
	Evicted    int64
	EdgeEvents int64

	ExfilEvents int64
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	sessions := len(c.sessions)
	c.mu.Unlock()

	c.reasonMu.Lock()
	reasons := make(map[string]int64, len(c.crossReasons))
	for k, v := range c.crossReasons {
		reasons[k] = v
	}
	c.reasonMu.Unlock()

	return Stats{
		Handled:          c.handled.Load(),
		Crossed:          c.crossed.Load(),
		Derived:          c.derived.Load(),
		HookToolCalls:    c.hookToolCalls.Load(),
		HookToolCrossed:  c.hookToolCrossed.Load(),
		Sessions:         sessions,
		CrossReasons:     reasons,
		InterposeReports: c.interposeReports.Load(),
		InterposeEvents:  c.interposeEvents.Load(),
		Provenance: ProvStats{
			Ingests:     c.provIngests.Load(),
			Registered:  c.provRegistered.Load(),
			Skipped:     c.provSkipped.Load(),
			Truncated:   c.provTruncated.Load(),
			Evicted:     c.provEvicted.Load(),
			EdgeEvents:  c.provEdgeEvents.Load(),
			ExfilEvents: c.provExfilEvents.Load(),
		},
		Shadow: ShadowStats{
			Deny:       c.shadowDeny.Load(),
			Ask:        c.shadowAsk.Load(),
			AllowAlert: c.shadowAlert.Load(),
		},
	}
}

func (c *Collector) InterestingFraction() float64 {
	h := c.handled.Load()
	if h == 0 {
		return 0
	}
	return float64(c.crossed.Load()) / float64(h)
}

func (s *sessionState) next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	return s.sequence
}

func (s *sessionState) zone(path string) string {
	s.mu.Lock()
	z := s.zoner
	s.mu.Unlock()
	if z == nil {
		return event.ZoneUnknown
	}
	return z.Zone(path)
}

func (s *sessionState) snapshotR2() event.R2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.r2
}

func kindFor(hookEvent string) (event.Kind, bool) {
	switch hookEvent {
	case hook.EvSessionStart:
		return event.KindSessionStart, true
	case hook.EvSessionEnd:
		return event.KindSessionEnd, true
	case hook.EvUserPromptSubmit:
		return event.KindPromptSubmit, true
	case hook.EvPreToolUse:
		return event.KindToolPre, true
	case hook.EvPostToolUse:
		return event.KindToolPost, true
	case hook.EvPostToolUseFailure:
		return event.KindToolFail, true
	case hook.EvPermissionRequest:
		return event.KindPermissionRequest, true
	case hook.EvPermissionDenied:
		return event.KindPermissionDenied, true
	case hook.EvInstructionsLoaded:
		return event.KindInstructionsLoaded, true
	case hook.EvConfigChange:
		return event.KindConfigChange, true
	case hook.EvFileChanged:
		return event.KindFileChanged, true
	case hook.EvSubagentStart:
		return event.KindSubagentStart, true
	case hook.EvSubagentStop:
		return event.KindSubagentStop, true
	case hook.EvPreCompact, hook.EvPostCompact:
		return event.KindCompact, true
	}
	return "", false
}

func opFor(toolName string) string {
	switch toolName {
	case "Read", "Grep", "Glob":
		return "read"
	case "Write", "Edit", "NotebookEdit":
		return "write"
	}
	return "unknown"
}

var addressingKeys = map[string]bool{
	"recipient": true, "recipients": true, "to": true, "cc": true, "bcc": true,
	"email": true, "emails": true, "user_email": true, "participants": true,
	"url": true, "channel": true, "address": true, "user": true,
	"file_path": true, "path": true, "notebook_path": true,
}

func renderPayload(p *hook.Payload) string {
	if p.ToolInput == nil {
		return ""
	}
	out := make([]byte, 0, 256)
	for k, v := range p.ToolInput {
		if addressingKeys[strings.ToLower(k)] {
			continue
		}
		out = append(out, []byte(fmt.Sprint(v))...)
		out = append(out, ' ')
	}
	return string(out)
}

func renderInput(p *hook.Payload) string {
	if p.ToolInput == nil {
		return ""
	}
	out := make([]byte, 0, 256)
	for _, v := range p.ToolInput {
		out = append(out, []byte(fmt.Sprint(v))...)
		out = append(out, ' ')
	}
	return string(out)
}

func toSecretHits(hits []redact.Hit) []event.SecretHit {
	if len(hits) == 0 {
		return nil
	}
	out := make([]event.SecretHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, event.SecretHit{Kind: h.Kind, Count: h.Count})
	}
	return out
}

func newEventID() string {

	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UTC().UnixMicro())
	}
	return fmt.Sprintf("%012x%s", time.Now().UTC().UnixMicro(), hex.EncodeToString(b[:]))
}
