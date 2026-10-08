package filter

import (
	"math/rand/v2"

	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
)

type Verdict struct {
	Cross  bool
	Reason string
}

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

var alwaysCross = map[event.Kind]bool{
	event.KindSessionStart:       true,
	event.KindSessionEnd:         true,
	event.KindToolFail:           true,
	event.KindPermissionRequest:  true,
	event.KindPermissionDenied:   true,
	event.KindInstructionsLoaded: true,
	event.KindConfigChange:       true,
	event.KindFileChanged:        true,
	event.KindSubagentStart:      true,
	event.KindSubagentStop:       true,
	event.KindCompact:            true,
	event.KindAmbitdHealth:       true,
	event.KindPromptSubmit:       true,
}

type Config struct {
	SampleRate float64

	DriftThreshold float64

	TrustedMCPServers map[string]bool
}

func DefaultConfig() Config {
	return Config{
		SampleRate:        0.005,
		DriftThreshold:    0.7,
		TrustedMCPServers: map[string]bool{},
	}
}

type Filter struct {
	cfg Config

	sample func() float64
}

func New(cfg Config) *Filter {
	return &Filter{cfg: cfg, sample: rand.Float64}
}

func NewWithSampler(cfg Config, sample func() float64) *Filter {
	return &Filter{cfg: cfg, sample: sample}
}

func (f *Filter) Decide(e *event.Event) Verdict {
	switch e.Kind {
	case event.KindGoalDriftScore:

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

	return Verdict{true, ReasonAlwaysKind}
}

func (f *Filter) decideMCPList(e *event.Event) Verdict {
	m := mcpBlock(e)
	if m == nil {

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

func Sanitize(s *event.SIEMEvent) *event.SIEMEvent {

	return s
}
