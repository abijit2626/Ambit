// Package interpose is the MCP interposer: the stdio passthrough that wraps one
// MCP server, hashes what it advertises, scans it, and reports.
//
// Three properties are load-bearing, and the tests enforce each because getting
// any of them wrong is silent.
//
// **It is a passthrough.** Frames are forwarded before they are parsed, byte for
// byte, and nothing the analyzer concludes can change what the client or the
// server receives. There is no verdict, no rewriting and no blocking — M1 observes
// and M3 is where enforcement starts, per docs/05-build-plan.md.
//
// **Every failure degrades to passthrough.** An unreachable ambitd, an unwritable
// baseline store, a hostile frame, a parse error: each is counted and reported, and
// none interrupts the developer's MCP traffic. The interposer sits between a
// developer and a tool they are using right now; an observability component that
// can break that has mistaken its own importance.
//
// **It holds no key and writes no sink.** Reports go to ambitd over loopback, and
// ambitd — which owns the HMAC key, the filter and the two sinks — builds the
// event. The interposer runs as the developer, as a child of the agent process,
// which is exactly the blast radius the key is meant to stay outside of.
package interpose

import (
	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/mcp"
)

// ReportSchemaVersion versions the loopback wire format between mcp-interpose and
// ambitd. The two are deployed together but not necessarily upgraded atomically,
// so a version mismatch has to be visible rather than produce silently empty
// fields.
const ReportSchemaVersion = 1

// Path is the loopback endpoint ambitd serves for interposer reports. It sits on
// the same listener as the hook endpoint: one loopback bind, one control, one
// thing to get wrong. See internal/loopback.
const Path = "/interpose"

// Trigger says what produced a report.
const (
	// TriggerToolsList is an ordinary tools/list response.
	TriggerToolsList = "tools_list"
	// TriggerListChanged is a tools/list response that followed a
	// notifications/tools/list_changed. The distinction is the whole point: a
	// surface that changes mid-session is a rug pull's arrival path, and an
	// analyst wants to know the listing was re-requested rather than routine.
	TriggerListChanged = "list_changed"
	// TriggerNotification is the notification itself, reported before the client
	// has re-listed, so the warning exists even if the re-listing never comes.
	TriggerNotification = "list_changed_notification"
	// TriggerShutdown is the end-of-process summary, carrying the counters that
	// corroborate this stream against the hook stream.
	TriggerShutdown = "shutdown"
)

// Report is one observation about one server, sent to ambitd over loopback.
//
// It carries findings, not events: ambitd assigns event ids, the endpoint and
// actor identity, the trust label from operator configuration, and decides what
// crosses to Wazuh. The interposer deliberately does not get an opinion on any of
// those.
type Report struct {
	SchemaV          int    `json:"schema_v"`
	InterposeVersion string `json:"interpose_version,omitempty"`
	TS               string `json:"ts"`

	// Server is the logical server name, which must match the key in .mcp.json.
	// It is what makes tool identity survive interposition: ambitd reconstructs
	// mcp__<server>__<tool>, so per-server rules and per-tool permission rules
	// keep working. See docs/08-mcp-interpose-decision.md on why the gateways
	// failed here.
	Server  string `json:"server"`
	Trigger string `json:"trigger"`

	// SessionID is best-effort and often empty. The MCP protocol carries no
	// Claude Code session id, and the interposer refuses to invent one: an
	// event correlated to the wrong session is worse than one correlated to
	// none. PID and PPID are what an investigator has instead. See the package
	// README note in cmd/mcp-interpose.
	SessionID string `json:"session_id,omitempty"`
	PID       int    `json:"pid,omitempty"`
	PPID      int    `json:"ppid,omitempty"`

	// ClientName and ClientVersion come from the initialize request: the agent's
	// own claim about what it is.
	ClientName    string         `json:"client_name,omitempty"`
	ClientVersion string         `json:"client_version,omitempty"`
	ServerInfo    mcp.ServerInfo `json:"server_info,omitempty"`

	// Approved reports whether this server's baseline has been approved by an
	// operator. Complete reports whether the listing was a full one rather than a
	// page of a paginated response; removals are only meaningful when it is true.
	Approved bool `json:"approved"`
	Complete bool `json:"complete"`

	Worst  string          `json:"worst,omitempty"`
	Counts baseline.Counts `json:"counts"`
	Tools  []ToolReport    `json:"tools,omitempty"`

	// CallsObserved and FramesUnparsed corroborate this stream against the hook
	// stream. A server whose tools are being called while the hook path reports
	// nothing — or the reverse — is the same class of signal as D7's OTel
	// discrepancy check: a collection path has gone quiet while work continues.
	CallsObserved  int64 `json:"calls_observed,omitempty"`
	FramesUnparsed int64 `json:"frames_unparsed,omitempty"`

	// Degraded and DegradedReason report the interposer's own health. A baseline
	// store that cannot be written means drift cannot be detected, and "no drift
	// found" must never be reported when the truth is "nothing was compared".
	Degraded       bool   `json:"degraded,omitempty"`
	DegradedReason string `json:"degraded_reason,omitempty"`
}

// ToolReport is the per-tool finding: D4's verdict and D5's classes for one tool.
type ToolReport struct {
	Tool          string   `json:"tool"`
	State         string   `json:"state"`
	MetadataHash  string   `json:"metadata_hash,omitempty"`
	PrevHash      string   `json:"prev_metadata_hash,omitempty"`
	ChangedFields []string `json:"changed_fields,omitempty"`

	// ScanClasses cross to Wazuh; ScanRules stay in the local spool, where they
	// are how a false-positive rate gets attributed to a specific pattern during
	// M1 tuning. Neither carries the matched text.
	ScanClasses []string `json:"scan_classes,omitempty"`
	ScanRules   []string `json:"scan_rules,omitempty"`

	// Annotations are carried as the server stated them, with absent distinct
	// from false, and are inputs to policy that may only make it stricter. A
	// server claiming readOnlyHint earns no relaxation anywhere. See docs/02.
	Annotations event.Annotations `json:"annotations"`

	// SchemaTruncated reports that the schema exceeded the scan bound, so a clean
	// scan of it is not a statement about the whole schema.
	SchemaTruncated bool `json:"schema_truncated,omitempty"`
}

// Notable reports whether a tool's findings are worth crossing to Wazuh.
//
// The quiet case — a tool that matches an approved baseline with no scan hits — is
// the overwhelming majority, and docs/04-data-model.md budgets mcp_list at one
// event per server per session. A 60-tool server would blow that budget sixtyfold
// for no signal, so the per-tool events that cross are the ones that say something.
// Everything is in the spool either way.
func (t ToolReport) Notable() bool {
	switch baseline.State(t.State) {
	case baseline.StateApproved, baseline.StatePending:
		return len(t.ScanClasses) > 0
	}
	return true
}
