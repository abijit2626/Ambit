// Package event defines the two representations of an agent event.
//
// The rich Event is what agentd computes and spools locally. The flat
// SIEMEvent in flat.go is what crosses to Wazuh. Keeping them separate is
// deliberate: Wazuh's JSON decoder cannot represent an array of objects, and a
// wide event risks the "Too many fields for JSON decoder" rejection, which is
// silent detection loss. See docs/04-data-model.md.
package event

// SchemaVersion is the current version of both representations. They move
// together so a consumer can trust one number.
const SchemaVersion = 2

// Kind enumerates event kinds. The set matches docs/04-data-model.md; the
// filter in internal/filter keys on these to decide what crosses to Wazuh.
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
	KindAgentdHealth       Kind = "agentd_health"
	KindGoalDriftScore     Kind = "goal_drift_score"
)

// Source identifies which collector produced the event.
type Source string

const (
	SourceHook      Source = "hook"
	SourceOTel      Source = "otel"
	SourceInterpose Source = "interpose"
	SourceAgentd    Source = "agentd"
)

// Decision is a policy verdict. In M0 the policy engine does not exist and
// every event carries DecisionNone: agentd is observe-only and must not change
// how any session behaves. See docs/05-build-plan.md M0.
type Decision string

const (
	DecisionNone       Decision = ""
	DecisionAllow      Decision = "allow"
	DecisionDeny       Decision = "deny"
	DecisionAsk        Decision = "ask"
	DecisionAllowAlert Decision = "allow_alert"
	DecisionFailOpen   Decision = "fail_open"
)

// Event is the rich internal representation. It stays local: spooled to the
// trajectory sink and pulled on request during investigation.
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
	AgentdVersion  string `json:"agentd_version"`
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
	// Trust is the operator-assigned label for the server. Only "internal"
	// relaxes anything; see docs/02 on annotations being one-directional.
	Trust string `json:"trust,omitempty"`
}

// Annotations mirrors MCP tool annotations. Pointers because "absent" and
// "false" mean different things: the spec says these are hints and clients
// should not trust them from an untrusted server, so a missing readOnlyHint
// must never be read as false and used to relax policy.
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
	// Command holds the raw command only when retention policy opts in. In M0
	// it is always empty.
	Command string `json:"command,omitempty"`
}

type PathRef struct {
	PathDigest string `json:"path_digest"`
	Zone       string `json:"zone"`
	Op         string `json:"op"`
}

type Features struct {
	Domains    []string    `json:"domains,omitempty"`
	URLs       []string    `json:"urls,omitempty"`
	Emails     []string    `json:"emails,omitempty"`
	IPs        []string    `json:"ips,omitempty"`
	HiEntropy  []string    `json:"hi_entropy,omitempty"`
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
	// FPNotable is the single high-specificity fingerprint selected for the
	// scalar Wazuh tripwire that stands in for D10; see docs/03.
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
	// SetBy references the event that most recently set a bit.
	SetBy string `json:"set_by,omitempty"`
	// Transition is true when this event set a bit that was previously unset.
	// The filter uses it so steady-state events do not all cross to Wazuh.
	Transition bool `json:"transition,omitempty"`
}

type Policy struct {
	Decision      Decision `json:"decision"`
	Reason        string   `json:"reason,omitempty"`
	RuleIDs       []string `json:"rule_ids,omitempty"`
	BundleVersion string   `json:"bundle_version,omitempty"`
	LatencyUS     int64    `json:"latency_us,omitempty"`
	// Shadow is true when the decision was computed but not returned to the
	// agent. M2 runs this way; M0 emits DecisionNone and Shadow false.
	Shadow bool `json:"shadow,omitempty"`
}

type Scores struct {
	GoalDrift    *float64 `json:"goal_drift"`
	DriftScorerV string   `json:"drift_scorer_v,omitempty"`
}

// PromptInfo carries prompt metadata. The text itself is held separately and
// never crosses to Wazuh; see docs/04 on prompt_submit being metadata-only.
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
