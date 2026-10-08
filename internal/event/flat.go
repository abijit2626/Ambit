package event

import "sort"

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

	MCPBaselineState string   `json:"mcp_baseline_state,omitempty"`
	MCPPrevHash      string   `json:"mcp_prev_metadata_hash,omitempty"`
	MCPChangedFields []string `json:"mcp_changed_fields,omitempty"`
	MCPScanClasses   []string `json:"mcp_scan_classes,omitempty"`
	MCPToolCount     int      `json:"mcp_tool_count,omitempty"`
	MCPTrigger       string   `json:"mcp_trigger,omitempty"`
	BashArgv0        string   `json:"bash_argv0,omitempty"`
	BashCommandClass string   `json:"bash_command_class,omitempty"`

	PathZone   string `json:"path_zone,omitempty"`
	PathOp     string `json:"path_op,omitempty"`
	PathDigest string `json:"path_digest,omitempty"`
	PathCount  int    `json:"path_count,omitempty"`

	SecretHitKinds []string `json:"secret_hit_kinds,omitempty"`
	ResultBytes    int      `json:"result_bytes,omitempty"`

	TaintLabels []string `json:"taint_labels,omitempty"`

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

	ConfigSource string `json:"config_source,omitempty"`

	ConfigLoadReason string `json:"config_load_reason,omitempty"`
	ConfigPathDigest string `json:"config_path_digest,omitempty"`
	ConfigZone       string `json:"config_zone,omitempty"`
	ConfigTrusted    *bool  `json:"config_trusted,omitempty"`

	HealthStatus        string `json:"health_status,omitempty"`
	HealthQueueDepth    int    `json:"health_queue_depth,omitempty"`
	HealthDroppedEvents int64  `json:"health_dropped_events,omitempty"`
}

var zoneSeverity = map[string]int{
	ZoneCredential: 50,
	ZoneSystem:     40,
	ZoneUntrusted:  30,
	ZoneHome:       20,
	ZoneWorkdir:    10,
	ZoneUnknown:    5,
}

const (
	ZoneCredential = "credential"
	ZoneSystem     = "system"
	ZoneUntrusted  = "untrusted"
	ZoneHome       = "home"
	ZoneWorkdir    = "workdir"
	ZoneUnknown    = "unknown"
)

func ZoneSeverity(zone string) int { return zoneSeverity[zone] }

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
			s.MCPBaselineState = m.BaselineState
			s.MCPPrevHash = m.PrevMetadataHash
			s.MCPChangedFields = m.ChangedFields
			s.MCPScanClasses = m.ScanClasses
			s.MCPToolCount = m.ToolCount
			s.MCPTrigger = m.Trigger
		}
		if b := t.Bash; b != nil {
			s.BashArgv0 = b.Argv0
			s.BashCommandClass = b.CommandClass
		}

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

		if f := t.InputFeatures; f != nil && len(f.SecretHits) > 0 {
			kinds := make([]string, 0, len(f.SecretHits))
			for _, h := range f.SecretHits {
				kinds = append(kinds, h.Kind)
			}
			sort.Strings(kinds)
			s.SecretHitKinds = kinds
		}
	}

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
		s.ConfigLoadReason = c.LoadReason
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
