package event

import "sort"

// SIEMEvent is the flattened, Wazuh-bound representation: scalar values and
// arrays of strings only.
//
// Two constraints from Wazuh's JSON decoder drive this shape, and neither is
// nesting depth — nested objects are addressable with dot notation and the
// shipped ruleset uses them three levels deep:
//
//  1. "An array of objects is not supported." Arrays of scalars are. So
//     Tool.Paths, Provenance.Edges and Features.SecretHits cannot be carried at
//     all and must collapse to scalars.
//  2. Field count. analysisd.decoder_order_size defaults to 256 (range
//     32-1024). A wide event risks rejection, which is silent detection loss.
//
// Target is under 40 fields. See docs/04-data-model.md.
type SIEMEvent struct {
	SchemaV int    `json:"schema_v"`
	EventID string `json:"event_id"`
	TS      string `json:"ts"`
	Src     Source `json:"src"`
	Kind    Kind   `json:"kind"`

	EndpointID    string `json:"endpoint_id"`
	OS            string `json:"os"`
	AmbitdVersion string `json:"ambitd_version"`
	UserID        string `json:"user_id"`
	OrgID         string `json:"org_id"`

	AgentKind              string `json:"agent_kind"`
	AgentVersion           string `json:"agent_version,omitempty"`
	AgentEntrypoint        string `json:"agent_entrypoint,omitempty"`
	AgentModel             string `json:"agent_model,omitempty"`
	PermissionMode         string `json:"permission_mode,omitempty"`
	SandboxEnabled         bool   `json:"sandbox_enabled"`
	SandboxStrictAllowlist bool   `json:"sandbox_strict_allowlist"`
	RepoRemoteDigest       string `json:"repo_remote_digest,omitempty"`
	RepoBranch             string `json:"repo_branch,omitempty"`

	SessionID       string `json:"session_id,omitempty"`
	PromptID        string `json:"prompt_id,omitempty"`
	Sequence        int64  `json:"sequence"`
	SubagentType    string `json:"subagent_type,omitempty"`
	ParentSessionID string `json:"parent_session_id,omitempty"`

	ToolName               string `json:"tool_name,omitempty"`
	ToolUseID              string `json:"tool_use_id,omitempty"`
	ToolMCPServer          string `json:"tool_mcp_server,omitempty"`
	ToolMCPTool            string `json:"tool_mcp_tool,omitempty"`
	ToolMCPTrust           string `json:"tool_mcp_trust,omitempty"`
	ToolMCPReadonlyHint    *bool  `json:"tool_mcp_readonly_hint,omitempty"`
	ToolMCPDestructiveHint *bool  `json:"tool_mcp_destructive_hint,omitempty"`
	ToolMCPOpenworldHint   *bool  `json:"tool_mcp_openworld_hint,omitempty"`
	ToolMCPMetadataHash    string `json:"tool_mcp_metadata_hash,omitempty"`
	BashArgv0              string `json:"bash_argv0,omitempty"`
	BashCommandClass       string `json:"bash_command_class,omitempty"`

	// PathZone, PathOp and PathDigest describe only the highest-severity path
	// of the call. PathCount preserves the cardinality D2 needs.
	PathZone   string `json:"path_zone,omitempty"`
	PathOp     string `json:"path_op,omitempty"`
	PathDigest string `json:"path_digest,omitempty"`
	PathCount  int    `json:"path_count,omitempty"`

	SecretHitKinds []string `json:"secret_hit_kinds,omitempty"`
	ResultBytes    int      `json:"result_bytes,omitempty"`

	TaintLabels []string `json:"taint_labels,omitempty"`
	// ProvEdge* describe only the highest-confidence edge. ProvEdgeCount
	// preserves how many there were.
	ProvEdgeCount      int     `json:"prov_edge_count,omitempty"`
	ProvEdgeClass      string  `json:"prov_edge_class,omitempty"`
	ProvEdgeConfidence float64 `json:"prov_edge_confidence,omitempty"`
	ProvEdgeFrom       string  `json:"prov_edge_from,omitempty"`
	ProvFPNotable      string  `json:"prov_fp_notable,omitempty"`
	ProvFPRole         string  `json:"prov_fp_role,omitempty"`

	R2A bool `json:"r2_a"`
	R2B bool `json:"r2_b"`
	R2C bool `json:"r2_c"`

	PolicyDecision      Decision `json:"policy_decision,omitempty"`
	PolicyReason        string   `json:"policy_reason,omitempty"`
	PolicyRuleID        string   `json:"policy_rule_id,omitempty"`
	PolicyBundleVersion string   `json:"policy_bundle_version,omitempty"`
	PolicyShadow        bool     `json:"policy_shadow,omitempty"`

	GoalDriftScore *float64 `json:"goal_drift_score,omitempty"`

	// ConfigZone and ConfigPathDigest carry config_change, file_changed and
	// instructions_loaded detail. Kept flat rather than in a nested object so
	// D6 and D8 rules address them directly.
	ConfigSource     string `json:"config_source,omitempty"`
	ConfigPathDigest string `json:"config_path_digest,omitempty"`
	ConfigZone       string `json:"config_zone,omitempty"`
	ConfigTrusted    *bool  `json:"config_trusted,omitempty"`

	HealthStatus        string `json:"health_status,omitempty"`
	HealthQueueDepth    int    `json:"health_queue_depth,omitempty"`
	HealthDroppedEvents int64  `json:"health_dropped_events,omitempty"`
}

// zoneSeverity ranks zones so Flatten can pick the one path that survives.
// Higher wins. credential outranks untrusted deliberately: a .env inside
// node_modules is a credential read, not a dependency read.
var zoneSeverity = map[string]int{
	ZoneCredential: 50,
	ZoneSystem:     40,
	ZoneUntrusted:  30,
	ZoneHome:       20,
	ZoneWorkdir:    10,
	ZoneUnknown:    5,
}

// Zone labels. These cross to Wazuh in cleartext while paths stay keyed
// digests: the zone carries the security meaning, so an external analyst who
// cannot resolve a digest can still triage. See docs/01 on the MSSP posture.
const (
	ZoneCredential = "credential"
	ZoneSystem     = "system"
	ZoneUntrusted  = "untrusted"
	ZoneHome       = "home"
	ZoneWorkdir    = "workdir"
	ZoneUnknown    = "unknown"
)

// ZoneSeverity exposes the ranking for callers that need to compare zones.
func ZoneSeverity(zone string) int { return zoneSeverity[zone] }

// Flatten projects the rich Event onto the Wazuh-bound representation.
//
// The projection is lossy by design and the losses are documented in
// docs/04-data-model.md: arrays of objects collapse to their highest-severity
// or highest-confidence member plus a count, raw feature fingerprints are not
// emitted at all, and operational-only fields are dropped. Anything a runbook
// needs beyond this is a spool-pull request.
func Flatten(e *Event) *SIEMEvent {
	s := &SIEMEvent{
		SchemaV:                SchemaVersion,
		EventID:                e.EventID,
		TS:                     e.TS,
		Src:                    e.Source,
		Kind:                   e.Kind,
		EndpointID:             e.Endpoint.EndpointID,
		OS:                     e.Endpoint.OS,
		AmbitdVersion:          e.Endpoint.AmbitdVersion,
		UserID:                 e.Actor.UserID,
		OrgID:                  e.Actor.OrgID,
		AgentKind:              e.Agent.Kind,
		AgentVersion:           e.Agent.Version,
		AgentEntrypoint:        e.Agent.Entrypoint,
		AgentModel:             e.Agent.Model,
		PermissionMode:         e.Agent.PermissionMode,
		SandboxEnabled:         e.Agent.Sandbox.Enabled,
		SandboxStrictAllowlist: e.Agent.Sandbox.StrictAllowlist,
		RepoRemoteDigest:       e.Agent.Repo.RemoteDigest,
		RepoBranch:             e.Agent.Repo.Branch,
		SessionID:              e.Session.SessionID,
		PromptID:               e.Session.PromptID,
		Sequence:               e.Session.Sequence,
		SubagentType:           e.Session.AgentType,
		ParentSessionID:        e.Session.ParentSessionID,
		TaintLabels:            e.Provenance.Taint,
		ProvFPNotable:          e.Provenance.FPNotable,
		ProvFPRole:             e.Provenance.FPRole,
		R2A:                    e.R2.A,
		R2B:                    e.R2.B,
		R2C:                    e.R2.C,
		PolicyDecision:         e.Policy.Decision,
		PolicyReason:           e.Policy.Reason,
		PolicyBundleVersion:    e.Policy.BundleVersion,
		PolicyShadow:           e.Policy.Shadow,
		GoalDriftScore:         e.Scores.GoalDrift,
	}

	// policy.rule_ids -> the deciding rule only. Triage cares which rule fired,
	// not the full evaluation trace.
	if len(e.Policy.RuleIDs) > 0 {
		s.PolicyRuleID = e.Policy.RuleIDs[0]
	}

	if t := e.Tool; t != nil {
		s.ToolName = t.Name
		s.ToolUseID = t.UseID
		s.ResultBytes = t.ResultBytes

		if m := t.MCP; m != nil {
			s.ToolMCPServer = m.Server
			s.ToolMCPTool = m.Tool
			s.ToolMCPTrust = m.Trust
			s.ToolMCPMetadataHash = m.MetadataHash
			s.ToolMCPReadonlyHint = m.Annotations.ReadOnlyHint
			s.ToolMCPDestructiveHint = m.Annotations.DestructiveHint
			s.ToolMCPOpenworldHint = m.Annotations.OpenWorldHint
		}
		if b := t.Bash; b != nil {
			s.BashArgv0 = b.Argv0
			s.BashCommandClass = b.CommandClass
		}

		// Array of objects -> highest-severity member plus count.
		if n := len(t.Paths); n > 0 {
			s.PathCount = n
			top := t.Paths[0]
			for _, p := range t.Paths[1:] {
				if zoneSeverity[p.Zone] > zoneSeverity[top.Zone] {
					top = p
				}
			}
			s.PathZone = top.Zone
			s.PathOp = top.Op
			s.PathDigest = top.PathDigest
		}

		// Secret hits -> kind strings only. Per-kind counts are dropped; the
		// value is never carried in either representation.
		if f := t.InputFeatures; f != nil && len(f.SecretHits) > 0 {
			kinds := make([]string, 0, len(f.SecretHits))
			for _, h := range f.SecretHits {
				kinds = append(kinds, h.Kind)
			}
			sort.Strings(kinds)
			s.SecretHitKinds = kinds
		}
	}

	// Array of objects -> highest-confidence member plus count.
	if n := len(e.Provenance.Edges); n > 0 {
		s.ProvEdgeCount = n
		top := e.Provenance.Edges[0]
		for _, edge := range e.Provenance.Edges[1:] {
			if edge.Confidence > top.Confidence {
				top = edge
			}
		}
		s.ProvEdgeClass = top.MatchClass
		s.ProvEdgeConfidence = top.Confidence
		s.ProvEdgeFrom = top.FromEvent
	}

	if c := e.Config; c != nil {
		s.ConfigSource = c.Source
		s.ConfigPathDigest = c.PathDigest
		s.ConfigZone = c.Zone
		trusted := c.Trusted
		s.ConfigTrusted = &trusted
	}

	if h := e.Health; h != nil {
		s.HealthStatus = h.Status
		s.HealthQueueDepth = h.QueueDepth
		s.HealthDroppedEvents = h.DroppedEvents
	}

	return s
}
