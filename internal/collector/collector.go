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
	"sync"
	"sync/atomic"
	"time"

	"github.com/abijit2626/indirect-prompt/internal/classify"
	"github.com/abijit2626/indirect-prompt/internal/config"
	"github.com/abijit2626/indirect-prompt/internal/event"
	"github.com/abijit2626/indirect-prompt/internal/features"
	"github.com/abijit2626/indirect-prompt/internal/filter"
	"github.com/abijit2626/indirect-prompt/internal/hook"
	"github.com/abijit2626/indirect-prompt/internal/redact"
)

// Sink is the subset of sink.Writer the collector needs, so tests can substitute.
type Sink interface {
	Write(v any) bool
}

// sessionState is the per-session state the collector keeps.
//
// In M0 this only tracks what is needed to populate events. The Rule-of-Two bits
// and the provenance fingerprint set live here in M2, which is why the type
// exists now rather than being inlined.
type sessionState struct {
	mu       sync.Mutex
	sequence int64
	cwd      string
	model    string
	permMode string
	zoner    *classify.Zoner
	// r2 is carried but never set in M0: no accounting yet, and emitting
	// half-computed bits would put untrustworthy fields in front of a reviewer.
	r2 event.R2
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

	mu       sync.Mutex
	sessions map[string]*sessionState

	handled atomic.Int64
	crossed atomic.Int64
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

	return &Collector{
		cfg:          opts.Config,
		hostname:     hostname,
		events:       opts.EventsSink,
		traj:         opts.TrajectorySink,
		filt:         filter.New(fc),
		ext:          opts.Extractor,
		red:          redact.New(),
		log:          opts.Logger,
		version:      opts.Version,
		sessions:     map[string]*sessionState{},
		crossReasons: map[string]int64{},
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

	// The spool gets everything, in the rich representation.
	c.traj.Write(e)

	// Wazuh gets the filtered, flattened slice.
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
			OS:            runtime.GOOS,
			AgentdVersion: c.version,
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
		c.fillPrompt(e, p)
	case event.KindToolPre, event.KindToolPost, event.KindToolFail, event.KindPermissionRequest, event.KindPermissionDenied:
		c.fillTool(e, p, st)
	case event.KindInstructionsLoaded, event.KindConfigChange, event.KindFileChanged:
		c.fillConfig(e, p, st)
	}
	return e
}

func (c *Collector) fillPrompt(e *event.Event, p *hook.Payload) {
	// The prompt text is retained in the rich event for the spool, redacted, so
	// the declared objective is available to M4's goal-drift scorer. It has no
	// field in the flattened representation and therefore cannot reach Wazuh.
	clean, hits := c.red.Redact(p.UserInput)
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

	if p.ToolResult != nil {
		resultText := fmt.Sprint(p.ToolResult)
		cleanResult, resultHits := c.red.Redact(resultText)
		t.ResultDigest = c.ext.Digest(resultText)
		t.ResultBytes = len(resultText)
		// Result features feed the provenance ingest set in M2. In M0 they are
		// computed and spooled so the M2 work starts from real data rather than
		// from a guess about what these look like.
		resultFeatures := c.ext.Extract(cleanResult)
		t.InputFeatures.SecretHits = append(t.InputFeatures.SecretHits, toSecretHits(resultHits)...)
		e.Provenance.FPNotable = features.NotableFingerprint(resultFeatures)
		if e.Provenance.FPNotable != "" {
			e.Provenance.FPRole = "ingest"
		}
	}

	e.Tool = t
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
		ci.Trusted = c.isTrustedRepoPath(path)
	}
	e.Config = ci
}

// isTrustedRepoPath reports whether an instruction file came from a trusted
// location. An untrusted one is a D8 candidate: a poisoned CLAUDE.md in a cloned
// repository, which InstructionsLoaded is the only event that reports.
func (c *Collector) isTrustedRepoPath(path string) bool {
	for _, prefix := range c.cfg.TrustedRepoPaths {
		if prefix != "" && len(path) >= len(prefix) && path[:len(prefix)] == prefix {
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
		st = &sessionState{
			cwd:      p.CWD,
			zoner:    classify.NewZoner(c.cfg.Home, p.CWD, c.cfg.ExtraUntrustedPaths),
			model:    p.Model,
			permMode: p.PermissionMode,
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

// Forget drops a session's state. Called on SessionEnd so long-lived agentd
// processes do not accumulate state for sessions that ended hours ago.
func (c *Collector) Forget(sessionID string) {
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()
}

// Stats reports collector counters for the health event.
type Stats struct {
	Handled      int64
	Crossed      int64
	Sessions     int
	CrossReasons map[string]int64
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
		Handled:      c.handled.Load(),
		Crossed:      c.crossed.Load(),
		Sessions:     sessions,
		CrossReasons: reasons,
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
