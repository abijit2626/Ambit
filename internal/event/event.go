package event

const SchemaVersion = 2

type Kind string

const (
	KindSessionStart       Kind = "session_start"
	KindSessionEnd         Kind = "session_end"
	KindPromptSubmit       Kind = "prompt_submit"
	KindToolPre            Kind = "tool_pre"
	KindToolPost           Kind = "tool_post"
	KindToolFail           Kind = "tool_fail"
	KindPermissionRequest  Kind = "permission_request"
	KindPermissionDenied   Kind = "permission_denied"
	KindInstructionsLoaded Kind = "instructions_loaded"
	KindConfigChange       Kind = "config_change"
	KindFileChanged        Kind = "file_changed"
	KindMCPList            Kind = "mcp_list"
	KindSubagentStart      Kind = "subagent_start"
	KindSubagentStop       Kind = "subagent_stop"
	KindCompact            Kind = "compact"
	KindAmbitdHealth       Kind = "ambitd_health"
	KindGoalDriftScore     Kind = "goal_drift_score"
)

const (
	MCPStateNew             = "new"
	MCPStatePending         = "pending"
	MCPStateApproved        = "approved"
	MCPStateDrift           = "drift"
	MCPStateDriftUnapproved = "drift_unapproved"
	MCPStateRemoved         = "removed"
	MCPStateUnavailable     = "unavailable"
)

type Source string

const (
	SourceHook      Source = "hook"
	SourceOTel      Source = "otel"
	SourceInterpose Source = "interpose"
	SourceAmbitd    Source = "ambitd"
)

type Decision string

const (
	DecisionNone       Decision = ""
	DecisionAllow      Decision = "allow"
	DecisionDeny       Decision = "deny"
	DecisionAsk        Decision = "ask"
	DecisionAllowAlert Decision = "allow_alert"
	DecisionFailOpen   Decision = "fail_open"
)

type Event struct {
	EventID    string `json:"event_id"`
	TS         string `json:"ts"`
	IngestedAt string `json:"ingested_at"`
	Source     Source `json:"source"`
	SchemaV    int    `json:"schema_v"`
	Kind       Kind   `json:"kind"`

	Endpoint Endpoint `json:"endpoint"`
	Actor    Actor    `json:"actor"`
	Agent    Agent    `json:"agent"`
	Session  Session  `json:"session"`

	Tool       *Tool       `json:"tool,omitempty"`
	Provenance Provenance  `json:"provenance"`
	R2         R2          `json:"r2"`
	Policy     Policy      `json:"policy"`
	Scores     Scores      `json:"scores"`
	Prompt     *PromptInfo `json:"prompt,omitempty"`
	Config     *ConfigInfo `json:"config,omitempty"`
	Health     *Health     `json:"health,omitempty"`
}

type Endpoint struct {
	EndpointID     string `json:"endpoint_id"`
	HostnameDigest string `json:"hostname_digest"`
	OS             string `json:"os"`
	AmbitdVersion  string `json:"ambitd_version"`
}

type Actor struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
}

type Agent struct {
	Kind           string  `json:"kind"`
	Version        string  `json:"version"`
	Entrypoint     string  `json:"entrypoint"`
	Model          string  `json:"model"`
	PermissionMode string  `json:"permission_mode"`
	CWDDigest      string  `json:"cwd_digest"`
	Repo           Repo    `json:"repo"`
	Sandbox        Sandbox `json:"sandbox"`
}

type Repo struct {
	RemoteDigest string `json:"remote_digest"`
	Branch       string `json:"branch"`
	Dirty        bool   `json:"dirty"`
}

type Sandbox struct {
	Enabled         bool `json:"enabled"`
	StrictAllowlist bool `json:"strict_allowlist"`
}

type Session struct {
	SessionID       string `json:"session_id"`
	PromptID        string `json:"prompt_id"`
	Sequence        int64  `json:"sequence"`
	AgentID         string `json:"agent_id,omitempty"`
	AgentType       string `json:"agent_type,omitempty"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
}

type Tool struct {
	Name          string    `json:"name"`
	UseID         string    `json:"use_id"`
	MCP           *MCP      `json:"mcp,omitempty"`
	Bash          *Bash     `json:"bash,omitempty"`
	Paths         []PathRef `json:"paths,omitempty"`
	InputDigest   string    `json:"input_digest"`
	ResultDigest  string    `json:"result_digest,omitempty"`
	ResultBytes   int       `json:"result_bytes,omitempty"`
	InputFeatures *Features `json:"input_features,omitempty"`
	ContentRef    string    `json:"content_ref,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type MCP struct {
	Server       string      `json:"server"`
	Tool         string      `json:"tool"`
	Annotations  Annotations `json:"annotations"`
	MetadataHash string      `json:"metadata_hash,omitempty"`

	Trust string `json:"trust,omitempty"`

	Classified bool     `json:"classified,omitempty"`
	Labels     []string `json:"labels,omitempty"`

	BaselineState string `json:"baseline_state,omitempty"`

	PrevMetadataHash string `json:"prev_metadata_hash,omitempty"`

	ChangedFields []string `json:"changed_fields,omitempty"`

	ScanClasses []string `json:"scan_classes,omitempty"`
	ScanRules   []string `json:"scan_rules,omitempty"`

	ToolCount int `json:"tool_count,omitempty"`

	Worst string `json:"worst,omitempty"`

	NewCount     int `json:"new_count,omitempty"`
	DriftCount   int `json:"drift_count,omitempty"`
	RemovedCount int `json:"removed_count,omitempty"`

	Trigger string `json:"trigger,omitempty"`

	Approved *bool `json:"approved,omitempty"`

	Complete *bool `json:"complete,omitempty"`

	ServerVersion string `json:"server_version,omitempty"`

	CallsObserved int64 `json:"calls_observed,omitempty"`
}

type Annotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

type Bash struct {
	Argv0         string `json:"argv0"`
	CommandClass  string `json:"command_class"`
	CommandDigest string `json:"command_digest"`

	Command string `json:"command,omitempty"`
}

type PathRef struct {
	PathDigest string `json:"path_digest"`
	Zone       string `json:"zone"`
	Op         string `json:"op"`
}

type Features struct {
	Domains   []string `json:"domains,omitempty"`
	URLs      []string `json:"urls,omitempty"`
	Emails    []string `json:"emails,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	HiEntropy []string `json:"hi_entropy,omitempty"`

	IBANs      []string    `json:"ibans,omitempty"`
	Shingles   []string    `json:"shingles,omitempty"`
	SecretHits []SecretHit `json:"secret_hits,omitempty"`
	Counts     Counts      `json:"counts"`
}

type SecretHit struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type Counts struct {
	Bytes int `json:"bytes"`
	Lines int `json:"lines"`
}

type Provenance struct {
	Taint      []string `json:"taint,omitempty"`
	IngestRefs []string `json:"ingest_refs,omitempty"`
	Edges      []Edge   `json:"edges,omitempty"`

	Exfil []Edge `json:"exfil,omitempty"`

	FPNotable string `json:"fp_notable,omitempty"`
	FPRole    string `json:"fp_role,omitempty"`
}

type Edge struct {
	FromEvent   string  `json:"from_event"`
	MatchClass  string  `json:"match_class"`
	MatchDigest string  `json:"match_digest"`
	Confidence  float64 `json:"confidence"`
}

type R2 struct {
	A bool `json:"a"`
	B bool `json:"b"`
	C bool `json:"c"`

	SetBy string `json:"set_by,omitempty"`

	Transition bool `json:"transition,omitempty"`
}

type Policy struct {
	Decision      Decision `json:"decision"`
	Reason        string   `json:"reason,omitempty"`
	RuleIDs       []string `json:"rule_ids,omitempty"`
	BundleVersion string   `json:"bundle_version,omitempty"`
	LatencyUS     int64    `json:"latency_us,omitempty"`

	Shadow bool `json:"shadow,omitempty"`

	Alternatives []ScopedVerdict `json:"alternatives,omitempty"`
}

type ScopedVerdict struct {
	Scoping  string   `json:"scoping"`
	Decision Decision `json:"decision"`
	RuleID   string   `json:"rule_id,omitempty"`
}

const (
	ScopingSession = "session"

	ScopingTurn = "turn"
)

type Scores struct {
	GoalDrift    *float64 `json:"goal_drift"`
	DriftScorerV string   `json:"drift_scorer_v,omitempty"`
}

type PromptInfo struct {
	Text       string `json:"text,omitempty"`
	TextDigest string `json:"text_digest"`
	Bytes      int    `json:"bytes"`
}

type ConfigInfo struct {
	Source     string `json:"source,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	PathDigest string `json:"path_digest,omitempty"`
	LoadReason string `json:"load_reason,omitempty"`
	ChangeType string `json:"change_type,omitempty"`
	Zone       string `json:"zone,omitempty"`
	Trusted    bool   `json:"trusted"`
}

type Health struct {
	Status        string `json:"status"`
	QueueDepth    int    `json:"queue_depth"`
	DroppedEvents int64  `json:"dropped_events"`
	UptimeSec     int64  `json:"uptime_sec"`
}
