// Package filter decides which events cross to Wazuh.
//
// This is load-bearing in both directions. Too permissive and the indexer drowns
// in ordinary file reads — Wazuh is a SIEM, not an analytics warehouse, and the
// estimate is ~300k events/day for 63 agents. Too restrictive and detection goes
// blind. The full trajectory stays in the local spool either way; only the
// security-relevant slice crosses. See docs/04-data-model.md.
package filter

import (
	"math/rand/v2"

	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
)

// Verdict says whether an event crosses and why. The reason is kept for the M0
// exit criterion that measures the interesting fraction: without it there is no
// way to tell which criterion is responsible for the volume.
type Verdict struct {
	Cross  bool
	Reason string
}

// Reasons for crossing.
const (
	ReasonAlwaysKind     = "always_kind"
	ReasonDecision       = "policy_decision"
	ReasonProvEdge       = "provenance_edge"
	ReasonR2Transition   = "r2_transition"
	ReasonSevereZone     = "severe_zone"
	ReasonSecretHit      = "secret_hit"
	ReasonNetworkCmd     = "network_command"
	ReasonMCPRisk        = "mcp_risk"
	ReasonMCPListing     = "mcp_listing"
	ReasonMCPFinding     = "mcp_finding"
	ReasonNotableFP      = "notable_fingerprint"
	ReasonSampled        = "sampled_remainder"
	ReasonDriftAbove     = "drift_above_threshold"
	ReasonNotInteresting = ""
)

// alwaysCross are the low-volume kinds that cross unconditionally. Each is
// either a detector input with no high-volume equivalent or is rare enough that
// volume is not a concern.
var alwaysCross = map[event.Kind]bool{
	event.KindSessionStart:       true, // D1 needs entrypoint and permission_mode
	event.KindSessionEnd:         true,
	event.KindToolFail:           true, // blocked-attempt signal
	event.KindPermissionRequest:  true,
	event.KindPermissionDenied:   true, // attack-attempt signal
	event.KindInstructionsLoaded: true, // D8
	event.KindConfigChange:       true, // D6
	event.KindFileChanged:        true, // D6
	event.KindSubagentStart:      true,
	event.KindSubagentStop:       true,
	event.KindCompact:            true, // needed to interpret R2 state
	event.KindAmbitdHealth:       true, // D7, D11
	event.KindPromptSubmit:       true, // metadata only; see Sanitize
}

// Config tunes the filter.
type Config struct {
	// SampleRate is the fraction of otherwise-uninteresting tool events that
	// cross anyway, so the SIEM holds enough ordinary traffic to baseline
	// against. 0.005 is the documented starting point.
	SampleRate float64
	// DriftThreshold is the goal-drift score at or above which a score event
	// crosses. Below it, scores stay in the spool.
	DriftThreshold float64
	// TrustedMCPServers are servers whose results do not by themselves make an
	// event interesting. Only an explicitly classified server qualifies: a
	// server merely claiming readOnlyHint earns nothing.
	TrustedMCPServers map[string]bool
}

func DefaultConfig() Config {
	return Config{
		SampleRate:        0.005,
		DriftThreshold:    0.7,
		TrustedMCPServers: map[string]bool{},
	}
}

// Filter decides what crosses.
type Filter struct {
	cfg Config
	// sample is injected so tests are deterministic.
	sample func() float64
}

func New(cfg Config) *Filter {
	return &Filter{cfg: cfg, sample: rand.Float64}
}

// NewWithSampler is for tests and for a deployment that wants a deterministic
// sampler keyed on the event id.
func NewWithSampler(cfg Config, sample func() float64) *Filter {
	return &Filter{cfg: cfg, sample: sample}
}

// Decide returns whether the event crosses to Wazuh.
func (f *Filter) Decide(e *event.Event) Verdict {
	switch e.Kind {
	case event.KindGoalDriftScore:
		// One score per tool call is the firehose again; only notable ones cross.
		if e.Scores.GoalDrift != nil && *e.Scores.GoalDrift >= f.cfg.DriftThreshold {
			return Verdict{true, ReasonDriftAbove}
		}
		return Verdict{false, ReasonNotInteresting}
	case event.KindToolPre, event.KindToolPost:
		return f.decideTool(e)
	case event.KindMCPList:
		return f.decideMCPList(e)
	}

	if alwaysCross[e.Kind] {
		return Verdict{true, ReasonAlwaysKind}
	}
	// Unknown kinds cross. A new event kind that silently stopped reaching the
	// SIEM would be a detection gap nobody notices; excess volume is at least
	// visible.
	return Verdict{true, ReasonAlwaysKind}
}

// decideMCPList decides which interposer listing events cross.
//
// docs/04-data-model.md budgets mcp_list at one event per server per session, and
// the per-server summary is that event: it always crosses, because the inventory of
// what the fleet trusts is the point of M1. The per-tool events carry the detail,
// and only the ones that say something cross — a 60-tool server matching its
// approved baseline would otherwise spend 60 events per session reporting that
// nothing happened, which is the firehose docs/04 exists to prevent. Every tool is
// in the local spool either way, so an investigation loses nothing.
//
// Note the direction of the default: anything that is not a quiet, known state
// crosses. A state this function has never heard of is a new verdict somebody added
// without updating the filter, and the safe reading of that is "interesting".
func (f *Filter) decideMCPList(e *event.Event) Verdict {
	m := mcpBlock(e)
	if m == nil {
		// A listing event with no MCP block is malformed. It crosses: a silent
		// drop here would hide a bug in our own emission path.
		return Verdict{true, ReasonMCPListing}
	}
	if m.Tool == "" {
		return Verdict{true, ReasonMCPListing}
	}
	if len(m.ScanClasses) > 0 {
		return Verdict{true, ReasonMCPFinding}
	}
	switch m.BaselineState {
	case event.MCPStateApproved, event.MCPStatePending:
		return Verdict{false, ReasonNotInteresting}
	}
	return Verdict{true, ReasonMCPFinding}
}

func mcpBlock(e *event.Event) *event.MCP {
	if e.Tool == nil {
		return nil
	}
	return e.Tool.MCP
}

func (f *Filter) decideTool(e *event.Event) Verdict {
	if e.Policy.Decision != event.DecisionNone && e.Policy.Decision != event.DecisionAllow {
		return Verdict{true, ReasonDecision}
	}
	if len(e.Provenance.Edges) > 0 {
		return Verdict{true, ReasonProvEdge}
	}
	// Only the transition crosses, not every subsequent event in a session whose
	// bits are already set — otherwise one untrusted fetch makes the rest of the
	// session unconditionally interesting.
	if e.R2.Transition {
		return Verdict{true, ReasonR2Transition}
	}
	if e.Provenance.FPNotable != "" {
		return Verdict{true, ReasonNotableFP}
	}

	if t := e.Tool; t != nil {
		for _, p := range t.Paths {
			if p.Zone == event.ZoneCredential || p.Zone == event.ZoneSystem {
				return Verdict{true, ReasonSevereZone}
			}
		}
		if t.InputFeatures != nil && len(t.InputFeatures.SecretHits) > 0 {
			return Verdict{true, ReasonSecretHit}
		}
		if t.Bash != nil && classify.IsNetworkClass(t.Bash.CommandClass) {
			return Verdict{true, ReasonNetworkCmd}
		}
		if m := t.MCP; m != nil {
			if m.Annotations.DestructiveHint != nil && *m.Annotations.DestructiveHint {
				return Verdict{true, ReasonMCPRisk}
			}
			// A server that has not been explicitly classified as trusted is
			// interesting. Note the direction: absence of classification makes
			// an event cross, and a server's own claim about itself never makes
			// one stop crossing.
			if m.Server != "" && !f.cfg.TrustedMCPServers[m.Server] {
				return Verdict{true, ReasonMCPRisk}
			}
		}
	}

	if f.cfg.SampleRate > 0 && f.sample() < f.cfg.SampleRate {
		return Verdict{true, ReasonSampled}
	}
	return Verdict{false, ReasonNotInteresting}
}

// Sanitize strips fields that must not cross even on an event that does.
//
// Currently prompt text: prompt_submit crosses because its presence or absence
// is D1's core signal, but the text itself is sensitive and no rule needs it.
// The text stays in the rich event in the local spool.
func Sanitize(s *event.SIEMEvent) *event.SIEMEvent {
	// The flattened representation never carries prompt text by construction —
	// there is no field for it. This function exists as the single place to add
	// such stripping, and as somewhere the intent is stated, so a future field
	// addition has an obvious home.
	return s
}
