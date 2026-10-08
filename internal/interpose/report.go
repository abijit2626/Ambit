package interpose

import (
	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/mcp"
)

const ReportSchemaVersion = 1

const Path = "/interpose"

const (
	TriggerToolsList = "tools_list"

	TriggerListChanged = "list_changed"

	TriggerNotification = "list_changed_notification"

	TriggerShutdown = "shutdown"
)

type Report struct {
	SchemaV          int    `json:"schema_v"`
	InterposeVersion string `json:"interpose_version,omitempty"`
	TS               string `json:"ts"`

	Server  string `json:"server"`
	Trigger string `json:"trigger"`

	SessionID string `json:"session_id,omitempty"`
	PID       int    `json:"pid,omitempty"`
	PPID      int    `json:"ppid,omitempty"`

	ClientName    string         `json:"client_name,omitempty"`
	ClientVersion string         `json:"client_version,omitempty"`
	ServerInfo    mcp.ServerInfo `json:"server_info,omitempty"`

	Approved bool `json:"approved"`
	Complete bool `json:"complete"`

	Worst  string          `json:"worst,omitempty"`
	Counts baseline.Counts `json:"counts"`
	Tools  []ToolReport    `json:"tools,omitempty"`

	CallsObserved  int64 `json:"calls_observed,omitempty"`
	FramesUnparsed int64 `json:"frames_unparsed,omitempty"`

	Degraded       bool   `json:"degraded,omitempty"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

type ToolReport struct {
	Tool          string   `json:"tool"`
	State         string   `json:"state"`
	MetadataHash  string   `json:"metadata_hash,omitempty"`
	PrevHash      string   `json:"prev_metadata_hash,omitempty"`
	ChangedFields []string `json:"changed_fields,omitempty"`

	ScanClasses []string `json:"scan_classes,omitempty"`
	ScanRules   []string `json:"scan_rules,omitempty"`

	Annotations event.Annotations `json:"annotations"`

	SchemaTruncated bool `json:"schema_truncated,omitempty"`
}

func (t ToolReport) Notable() bool {
	switch baseline.State(t.State) {
	case baseline.StateApproved, baseline.StatePending:
		return len(t.ScanClasses) > 0
	}
	return true
}
