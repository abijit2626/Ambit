// Package collector turns Claude Code hook payloads into normalized events and
// writes them to the two sinks.
//
// The split is the design's core constraint: everything needing live session
// state or an inline verdict lives here on the endpoint, because PreToolUse needs
// an answer in single-digit milliseconds and no SIEM can return one. In M0 there
// is no verdict yet — the collector observes and nothing more. See
// docs/02-architecture.md.
package collector

import (
	"crypto/rand"
	"encoding/hex"
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
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/filter"
	"github.com/abijit2626/ambit/internal/gate"
	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/prov"
	"github.com/abijit2626/ambit/internal/r2"
	"github.com/abijit2626/ambit/internal/redact"
)

// runtimeGOOS is a variable so tests can pin the value.
var runtimeGOOS = runtime.GOOS

// Sink is the subset of sink.Writer the collector needs, so tests can substitute.
type Sink interface {
	Write(v any) bool
}

// sessionState is the per-session state the collector keeps.
//
// It is keyed on Claude Code's session_id (see (c *Collector) session below),
// which is also the unit Rule-of-Two accounting uses: monotonic bits that never
// clear within a session (docs/03-detection.md, Layer 1), shipped in shadow
// mode specifically to measure how fast a session saturates to all three
// before choosing a narrower scoping. The provenance fingerprint set (prov) is
// session-scoped for the same reason and with the same open question: it lives and
// dies with this struct, so a /clear that mints a new session_id starts it empty.
type sessionState struct {
	mu       sync.Mutex
	sequence int64
	cwd      string
	model    string
	permMode string
	zoner    *classify.Zoner
	// r2 accumulates monotonically for the lifetime of this sessionState. Never
	// cleared by anything short of Collector.Forget (SessionEnd) — not by
	// PreCompact/PostCompact (clearing bit A on compaction is unsound,
	// since a summary can still carry an injected instruction) and there is no
	// dedicated hook event for /clear to even consider clearing on. r2.Transition
	// is deliberately never persisted here: it is meaningful only for the one
	// event that caused it, so setR2Bits returns it per-call rather than storing
	// it, and a caller reading r2 directly (snapshotR2) always sees it false.
	r2 event.R2
	// turnPrompt and turnBits are the same accounting scoped to one prompt turn: bits
	// reset when prompt_id changes. They feed only the gate's alternative verdict, so
	// the per-turn scoping (docs/03 candidate 3) can be measured beside the session one
	// without changing anything the session bits drive. An event with no prompt_id stays
	// in the current turn, so a client that never sends one degrades turn scoping to
	// session scoping rather than to a fresh turn per event.
	turnPrompt string
	turnBits   r2.Bits
	// prov is the provenance engine's per-session fingerprint set. It has its own
	// lock, so it is deliberately not guarded by mu: the hook path takes mu only to
	// read or write scalar fields, and holding it across a set intersection would
	// serialize unrelated requests for the same session for no benefit.
	prov *prov.Set
	// sens is a second fingerprint set, of values that sensitive reads (bit B) returned.
	// It feeds the exfil edges on acting calls. Same engine, same bounds and novelty rule
	// as prov: a value the user typed is theirs to send and is never registered.
	sens *prov.Set
}

// priorBits is what each scoping held before an event's own bits were applied: the
// input the gate needs, since its rows are about acting AFTER a bit was set.
type priorBits struct {
	session, turn r2.Bits
}

// setR2Bits ORs newBits into the session's Rule-of-Two state and returns the
// event.R2 snapshot for the ONE event that triggered this call: the cumulative
// bits, plus Transition true and SetBy set only when this call caused a bit to
// flip from unset to set. It also returns the bits each scoping held before this
// call, read under the same lock that applies the new ones: two concurrent requests
// for one session must not both see the state from before either of them.
//
// Calling this twice for the same tool call (once on PreToolUse, once on
// PostToolUse) is expected, not a bug: PostToolUse additionally carries the
// tool's result, so it can contribute bits PreToolUse could not have known
// about (a secret surfacing only in the output, for one). Re-applying the
// same input-side bits on the second call is a no-op under monotonic OR, and
// will not report a second Transition for something that already transitioned.
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

// Collector implements hook.Handler.
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
	// webDomainTrust holds keyed digests of cfg.TrustedContentDomains,
	// precomputed once so a WebFetch/WebSearch classification never re-digests
	// the operator's list. Nil or empty means nothing is trusted, the safe
	// default.
	webDomainTrust map[string]bool

	mu       sync.Mutex
	sessions map[string]*sessionState

	handled atomic.Int64
	crossed atomic.Int64
	// hookToolCalls counts tool events seen on the hook path, for comparison
	// against the OTel stream. See OTel() on why the comparison is coarse.
	hookToolCalls atomic.Int64
	// The provenance counters are summed across sessions, because a session's own
	// prov.Stats disappears at SessionEnd and truncation has to stay visible after
	// that. provTruncated and provEvicted are the ones to watch: either being
	// non-zero means some "no edge" was produced by an incomplete set.
	provIngests    atomic.Int64
	provRegistered atomic.Int64
	provSkipped    atomic.Int64
	provTruncated  atomic.Int64
	provEvicted    atomic.Int64
	provEdgeEvents atomic.Int64
	// provExfilEvents counts acting calls that carried a value a sensitive read returned.
	provExfilEvents atomic.Int64
	// shadowDeny, shadowAsk and shadowAlert count the gate's session-scoped shadow
	// verdicts: what enforcement would have done, had it been on.
	shadowDeny    atomic.Int64
	shadowAsk     atomic.Int64
	shadowAlert   atomic.Int64
	otelRecords   atomic.Int64
	otelToolCalls atomic.Int64
	otelLastSeen  atomic.Int64
	// interposeReports and interposeEvents count the third collection path. They
	// are separate from handled/crossed so the M0 interesting-fraction figure
	// stays comparable against a cohort that ran without an interposer.
	interposeReports atomic.Int64
	interposeEvents  atomic.Int64
	// crossReasons counts why events crossed. This is the M0 exit criterion that
	// measures the interesting fraction; without per-reason counts there is no
	// way to tell which criterion drives the volume.
	reasonMu     sync.Mutex
	crossReasons map[string]int64
}

// Options construct a Collector.
type Options struct {
	Config         config.Config
	EventsSink     Sink
	TrajectorySink Sink
	Extractor      *features.Extractor
	Logger         *slog.Logger
	Version        string
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
		// The same reduction Extract applies to an extracted domain, so a
		// configured "www.example.com" and an extracted "example.com" compare
		// equal — see features.Registrable's comment for why this has to be
		// the same function rather than a second implementation.
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
	}
}

// Handle processes a hook payload. It must not block: it is called on the hook's
// synchronous path, and both sinks are fire-and-forget by contract.
func (c *Collector) Handle(p *hook.Payload) {
	c.handled.Add(1)
	e := c.build(p)
	if e == nil {
		return
	}
	if e.Kind == event.KindToolPre || e.Kind == event.KindToolPost {
		c.hookToolCalls.Add(1)
	}

	c.emit(e)

	// The session is over, so its state goes. Forget documents itself as called on
	// SessionEnd, and nothing called it: every session an ambitd process ever saw
	// stayed in memory until the process restarted, which the provenance
	// fingerprint set (up to 8192 entries per session) turns from a rounding error
	// into real growth. After emit, not before, so the SessionEnd event itself still
	// carries the session's final Rule-of-Two state.
	if p.HookEventName == hook.EvSessionEnd {
		c.Forget(p.SessionID)
	}
}

// emit writes one event to both sinks: the spool gets everything in the rich
// representation, Wazuh gets the filtered, flattened slice. Every producer — the
// hook path, the OTel path, the interposer — goes through here, so the filter and
// the two-sink invariant have exactly one enforcement point.
func (c *Collector) emit(e *event.Event) {
	c.traj.Write(e)

	v := c.filt.Decide(e)
	c.recordReason(v)
	if v.Cross {
		c.crossed.Add(1)
		c.events.Write(filter.Sanitize(event.Flatten(e)))
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

// build maps a hook payload onto a normalized event. Returns nil for events the
// collector does not model.
func (c *Collector) build(p *hook.Payload) *event.Event {
	kind, ok := kindFor(p.HookEventName)
	if !ok {
		return nil
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
		// M0 emits no decision. DecisionNone is distinct from DecisionAllow:
		// "no opinion" is what keeps the session's behavior unchanged.
		Policy: event.Policy{Decision: event.DecisionNone},
	}
	if c.hostname != "" {
		// Digested, not carried: the hostname is endpoint-identifying and a
		// monitoring firm gets endpoint_id for that purpose instead.
		e.Endpoint.HostnameDigest = c.ext.Digest(c.hostname)
	}

	switch kind {
	case event.KindPromptSubmit:
		c.fillPrompt(e, p, st)
	case event.KindToolPre, event.KindToolPost, event.KindToolFail, event.KindPermissionRequest, event.KindPermissionDenied:
		c.fillTool(e, p, st)
	case event.KindInstructionsLoaded, event.KindConfigChange, event.KindFileChanged:
		c.fillConfig(e, p, st)
	}
	return e
}

func (c *Collector) fillPrompt(e *event.Event, p *hook.Payload, st *sessionState) {
	// The prompt text is retained in the rich event for the spool, redacted, so
	// the declared objective is available to M4's goal-drift scorer. It has no
	// field in the flattened representation and therefore cannot reach Wazuh.
	clean, hits := c.red.Redact(p.UserInput)

	// What the user wrote is not introduced by anything the agent later ingests, so
	// it is declared to the provenance engine. Extracted from the redacted text, for
	// the same reason tool input is: a secret must not become a fingerprint. The
	// features themselves are not kept on the event; only the engine holds them.
	declared := c.ext.Extract(clean)
	st.prov.Declare(declared)
	st.sens.Declare(declared)
	e.Prompt = &event.PromptInfo{
		Text:       clean,
		TextDigest: c.ext.Digest(p.UserInput),
		Bytes:      len(p.UserInput),
	}
	if len(hits) > 0 {
		c.log.Warn("secret material detected in a user prompt", "kinds", len(hits))
	}
}

func (c *Collector) fillTool(e *event.Event, p *hook.Payload, st *sessionState) {
	t := &event.Tool{Name: p.ToolName, UseID: p.ToolUseID, Error: p.ToolError}

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
	}

	if cmd := p.Command(); cmd != "" {
		argv0, class := classify.Bash(cmd)
		t.Bash = &event.Bash{
			Argv0:        argv0,
			CommandClass: class,
			// The raw command is digested, never carried: it routinely contains
			// paths and sometimes credentials.
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

	// Feature extraction runs over the redacted text, so a secret can never
	// become a fingerprint that then travels as a "high-entropy token".
	inputText := renderInput(p)
	cleanInput, inputHits := c.red.Redact(inputText)
	t.InputDigest = c.ext.Digest(inputText)
	t.InputFeatures = c.ext.Extract(cleanInput)
	t.InputFeatures.SecretHits = toSecretHits(inputHits)

	// The payload of an acting call, without its addressing fields, is what the exfil
	// match reads. Computed only for PreToolUse, the one place it is used.
	var payloadFeatures *event.Features
	if e.Kind == event.KindToolPre {
		cleanPayload, _ := c.red.Redact(renderPayload(p))
		payloadFeatures = c.ext.Extract(cleanPayload)
	}

	// resultFeatures is nil unless the payload carries a result. It is declared out
	// here because the provenance ingest below, which needs the R2 bits, runs after
	// the block that computes it.
	var resultFeatures *event.Features
	if p.ToolResult != nil {
		resultText := fmt.Sprint(p.ToolResult)
		cleanResult, resultHits := c.red.Redact(resultText)
		t.ResultDigest = c.ext.Digest(resultText)
		t.ResultBytes = len(resultText)
		resultFeatures = c.ext.Extract(cleanResult)
		t.InputFeatures.SecretHits = append(t.InputFeatures.SecretHits, toSecretHits(resultHits)...)
		e.Provenance.FPNotable = features.NotableFingerprint(resultFeatures)
		if e.Provenance.FPNotable != "" {
			e.Provenance.FPRole = "ingest"
		}
	}

	e.Tool = t

	// Rule-of-Two accounting applies only to PreToolUse and PostToolUse: a call
	// that was denied (PermissionRequest/PermissionDenied) or that failed
	// (ToolFail) did not actually read, write, or reach anything, and setting a
	// bit for an action that never happened would manufacture exactly the kind
	// of untrustworthy signal the shadow-mode measurement depends on being
	// real. e.Tool is still built for these kinds above, for investigation.
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
}

// shadowGate records the Rule-of-Two gate's verdict on a PreToolUse without returning
// it. Nothing here reaches Claude Code: the hook's decider is hook.ObserveOnly and
// answers {} before this runs. The verdict exists to measure, on real sessions, how often
// each row of docs/03's table would have stopped or prompted a developer.
//
// A row that does not fire leaves Policy at its zero value, so an ordinary event does not
// grow by a bundle version and a shadow flag; the turn-scoped verdict is recorded either
// way, because "the turn scoping would NOT have fired here" is half of the comparison.
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

// fillProvenance runs the provenance engine for one tool event: the intersection
// on PreToolUse, the ingest on PostToolUse, and the session taint label for either.
// It changes nothing the agent can observe; the result is fields on the event.
//
// The intersection runs on PreToolUse only. docs/03 says "on every PreToolUse", and
// the same call also produces a PostToolUse (and, if it is prompted, a
// PermissionRequest) carrying the very same input: matching on all of them would
// report one action as two or three edges, and rule 100283 would page for each.
func (c *Collector) fillProvenance(e *event.Event, t *event.Tool, st *sessionState, bits r2.Bits, result, payload *event.Features) {
	if bits.A {
		// Layer 2a, session taint: bit A as a label. A label rides on the event that
		// first introduces it and not on every later one, the same transition
		// discipline Rule-of-Two uses, so a long session does not widen every event.
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
		// Only an action that can act or reach outside can carry data out, so only
		// those are matched against what sensitive reads returned.
		if bits.C {
			if exfil := st.sens.Match(payload); len(exfil) > 0 {
				e.Provenance.Exfil = exfil
				c.provExfilEvents.Add(1)
			}
		}
	case event.KindToolPost:
		// Only untrusted ingest registers. bit A is the same predicate Rule-of-Two
		// uses for "untrusted input", so the two layers cannot disagree about what
		// counts: a result is tracked exactly when it moved the session toward the
		// first bit of the Rule of Two.
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
		// A result that set bit B is private data the session now holds. A result can be
		// both (a mailbox is untrusted content and private data) and then feeds both.
		if bits.B && result != nil {
			res := st.sens.Ingest(e.EventID, result, t.InputFeatures)
			c.provTruncated.Add(int64(res.Truncated))
			c.provEvicted.Add(int64(res.Evicted))
		}
	}
}

// maxTaintLabelsPerEvent bounds how many labels one event can carry, because the
// flattened event is under a field budget (see event's TestSIEMEventFieldBudgetPerKind)
// and the web label is per-domain.
const maxTaintLabelsPerEvent = 4

// taintLabels names where a bit-A tool event's untrusted input came from. The forms
// follow docs/04's example ("web:hmac:...", "mcp:github"). Domains are keyed
// digests, never names; an MCP server name is operator-configured and is cleartext
// everywhere else in the schema already.
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
			// WebSearch carries no URL to take a domain from.
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

// mcpUntrusted reports whether an MCP call's input counts as untrusted: by its labels
// when the operator classified the tool, otherwise by the server-level default.
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

// webUntrusted reports whether a WebFetch/WebSearch result's domain is not on
// the operator's trusted-content list — Rule-of-Two bit A's first bullet.
//
// An empty Domains set (WebSearch typically carries no URL to extract one
// from; a WebFetch whose target didn't match the extractor's regex) is
// treated as untrusted: an unverifiable domain gets the same conservative
// default as an unclassified MCP server, not the benefit of the doubt.
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
		// An untrusted zone overrides the trusted-repo prefix, and that precedence is
		// the whole point of D8. A CLAUDE.md inside node_modules of a trusted
		// repository is dependency-carried instruction content — the repo-carried
		// injection route — yet the prefix check alone calls it trusted, because the
		// dependency directory sits under a trusted path. Zone classification exists
		// to catch exactly that, so it wins.
		ci.Trusted = c.isTrustedRepoPath(path) && ci.Zone != event.ZoneUntrusted
	}
	e.Config = ci

	// Rule-of-Two bit A, fourth bullet: only InstructionsLoaded is an ingest
	// event here. ConfigChange and FileChanged are D6/D8 signals about the
	// endpoint's own configuration, not content the agent reads as context, so
	// they contribute nothing to R2.
	if e.Kind == event.KindInstructionsLoaded {
		bits := r2.ClassifyInstructionsLoaded(ci.Trusted)
		e.R2, _ = st.setR2Bits(bits, e.EventID, e.Session.PromptID)
		// An untrusted instruction file taints the session like any other bit-A
		// source. It cannot feed the fingerprint set: the hook payload carries a path
		// and no content, and reading an untrusted file from the daemon would be a
		// new capability this layer does not get to assume.
		if bits.A && st.prov.AddTaint("instructions:untrusted") {
			e.Provenance.Taint = append(e.Provenance.Taint, "instructions:untrusted")
		}
	}
}

// isTrustedRepoPath reports whether an instruction file came from a trusted
// location. An untrusted one is a D8 candidate: a poisoned CLAUDE.md in a cloned
// repository, which InstructionsLoaded is the only event that reports.
//
// The comparison is by path segment, after normalization. A string-prefix test treats
// /src/myrepo-evil/CLAUDE.md as inside a trusted /src/myrepo, which would let a
// poisoned repository with a similar name slip past D8; and on Windows it would miss
// C:\Users\Dev\src\myrepo against a configured c:/users/dev/src/myrepo.
func (c *Collector) isTrustedRepoPath(path string) bool {
	for _, trusted := range c.cfg.TrustedRepoPaths {
		if classify.PathWithin(path, trusted) {
			return true
		}
	}
	return false
}

// session finds or creates the state for p's session_id.
//
// This is the concrete answer this codebase gives to the subagent question
// (docs/03-detection.md, Layer 1), and it costs no extra code: Claude Code gives a subagent the SAME top-level session_id as its
// parent, distinguished only by agent_id/agent_type (code.claude.com/docs/en/hooks,
// "the input carries the agent_id and agent_type... that identify the
// subagent" — no separate parent-session field is documented). Keying
// sessionState on session_id alone therefore means a subagent's tool calls
// accumulate into, and read from, the exact same Rule-of-Two bits as its
// parent — the conservative default of inheriting, achieved by construction rather than by a parent-bits-copy this function
// would otherwise need to implement and get wrong.
//
// The other half of the question — a new session_id — is a genuine reset under this
// scheme, for ALL three bits, not just bit A. `/clear` is reported to call
// regenerateSessionId() without re-firing SessionStart (anthropics/claude-code
// issue #70606; a community report, not primary documentation), so the
// first post-/clear event lands on a fresh, empty sessionState here. That is
// unsound for bits B and C — the credential already read or
// the tool already reachable does not actually reset just because the context
// did — and this implementation does not solve that; it is the behavior
// shadow mode needs to measure the cost of before the scoping can be chosen
// rather than assumed.
func (c *Collector) session(p *hook.Payload) *sessionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.sessions[p.SessionID]
	if !ok {
		st = &sessionState{
			cwd:      p.CWD,
			zoner:    classify.NewZoner(c.cfg.Home, p.CWD, c.cfg.ExtraUntrustedPaths),
			model:    p.Model,
			permMode: p.PermissionMode,
			prov:     prov.New(prov.Options{CommonDomains: c.webDomainTrust}),
			sens:     prov.New(prov.Options{CommonDomains: c.webDomainTrust}),
		}
		c.sessions[p.SessionID] = st
	}
	// Later events carry fresher values for fields that change mid-session.
	st.mu.Lock()
	if p.PermissionMode != "" {
		st.permMode = p.PermissionMode
	}
	if p.Model != "" {
		st.model = p.Model
	}
	if p.CWD != "" && p.CWD != st.cwd {
		// CwdChanged is a real event; rebuild the zoner so workdir classification
		// follows the session rather than going stale.
		st.cwd = p.CWD
		st.zoner = classify.NewZoner(c.cfg.Home, p.CWD, c.cfg.ExtraUntrustedPaths)
	}
	st.mu.Unlock()
	return st
}

// Forget drops a session's state. Called on SessionEnd so long-lived ambitd
// processes do not accumulate state for sessions that ended hours ago.
func (c *Collector) Forget(sessionID string) {
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()
}

// Stats reports collector counters for the health event.
type Stats struct {
	Handled          int64
	Crossed          int64
	Sessions         int
	CrossReasons     map[string]int64
	InterposeReports int64
	InterposeEvents  int64
	// Provenance is the engine's account of itself, summed across sessions.
	Provenance ProvStats
	// Shadow counts the gate's session-scoped verdicts by decision. None was returned.
	Shadow ShadowStats
}

// ShadowStats count what the Rule-of-Two gate would have decided.
type ShadowStats struct {
	Deny       int64
	Ask        int64
	AllowAlert int64
}

// ProvStats are the provenance engine's counters. Truncated and Evicted are the two
// that matter operationally: either being non-zero means some session's fingerprint
// set was incomplete, so an absent edge there is weaker evidence than it looks.
type ProvStats struct {
	Ingests    int64 // tool results that registered at least one fingerprint
	Registered int64 // fingerprints stored
	Skipped    int64 // not stored: the user or the agent had already supplied them
	Truncated  int64 // dropped because one result exceeded its per-ingest cap
	Evicted    int64 // discarded to stay within the per-session cap
	EdgeEvents int64 // action events that carried at least one edge
	// ExfilEvents are acting calls that carried a value a sensitive read returned.
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

// InterestingFraction is the M0 exit metric: the share of handled events that
// crossed to Wazuh. The design estimates 2-5%; a materially higher number means
// the criteria tighten before M1.
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

// opFor guesses read versus write from the tool name. Read, Grep and Glob read;
// Write, Edit and NotebookEdit write. Anything else is unknown rather than
// assumed, because assuming "read" would understate a write.
func opFor(toolName string) string {
	switch toolName {
	case "Read", "Grep", "Glob":
		return "read"
	case "Write", "Edit", "NotebookEdit":
		return "write"
	}
	return "unknown"
}

// renderInput flattens tool_input to text for feature extraction. Values only:
// the keys are tool-schema names and contribute nothing but noise to
// fingerprinting.
// addressingKeys are tool_input fields that say WHERE an action goes rather than WHAT it
// carries: a recipient, a channel, a URL, a path. A private value there is the user
// addressing someone they know (a meeting participant, a payee), which the AgentDojo
// measurement showed is as common in benign sessions as in hostile ones. A private value in
// the remaining fields (a subject, a body, content) is data leaving. Matched by name,
// case-insensitively; this is a convention, not a schema, and a tool that puts its payload
// in a field named like this one hides it from the exfil match.
var addressingKeys = map[string]bool{
	"recipient": true, "recipients": true, "to": true, "cc": true, "bcc": true,
	"email": true, "emails": true, "user_email": true, "participants": true,
	"url": true, "channel": true, "address": true, "user": true,
	"file_path": true, "path": true, "notebook_path": true,
}

// renderPayload is renderInput without the addressing fields.
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
	// Time-ordered prefix plus randomness: sortable like a ULID without adding a
	// dependency for it.
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UTC().UnixMicro())
	}
	return fmt.Sprintf("%012x%s", time.Now().UTC().UnixMicro(), hex.EncodeToString(b[:]))
}
