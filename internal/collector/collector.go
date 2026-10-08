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

	hookToolCalls atomic.Int64

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
}

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

		Policy: event.Policy{Decision: event.DecisionNone},
	}
	if c.hostname != "" {

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

	clean, hits := c.red.Redact(p.UserInput)

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
