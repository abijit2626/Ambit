package collector

import (
	"sync/atomic"
	"time"

	"github.com/abijit2626/indirect-prompt/internal/event"
	"github.com/abijit2626/indirect-prompt/internal/hook"
	"github.com/abijit2626/indirect-prompt/internal/otlp"
)

// otelToolEvents are the OTel log event names that correspond to a tool call.
// These are what the discrepancy counter compares against the hook stream.
var otelToolEvents = map[string]bool{
	"claude_code.tool_decision": true,
	"claude_code.tool_result":   true,
}

// HandleOTel consumes decoded OTLP records.
//
// OTel records go to the SPOOL ONLY. They never cross to Wazuh: the stream is
// content-rich and high-volume, and the hook stream already carries the
// security-relevant slice with better structure. What OTel is for here is being a
// SECOND, INDEPENDENT path — the hook endpoint dies with agentd, while OTel's
// destination is pinned in managed settings with developer-set variables removed.
// Losing one while the other continues is the discrepancy detector D7 keys on,
// and that discrepancy is the point. See docs/02-architecture.md.
func (c *Collector) HandleOTel(records []otlp.Record) {
	for _, r := range records {
		c.otelRecords.Add(1)
		if otelToolEvents[r.Name] {
			c.otelToolCalls.Add(1)
		}
		if e := c.buildOTel(r); e != nil {
			c.traj.Write(e)
		}
	}
	c.otelLastSeen.Store(time.Now().UnixNano())
}

func (c *Collector) buildOTel(r otlp.Record) *event.Event {
	sessionID := r.SessionID()

	kind := event.KindToolPost
	switch r.Name {
	case "claude_code.tool_decision":
		kind = event.KindToolPre
	case "claude_code.tool_result":
		kind = event.KindToolPost
	default:
		// Anything else is recorded for the spool but is not a tool observation.
		// Deliberately not dropped: an unmodelled OTel event that vanished would
		// be a blind spot in the stream whose whole job is corroboration.
		kind = event.KindAgentdHealth
	}

	ts := r.TS
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	e := &event.Event{
		EventID:    newEventID(),
		TS:         ts.Format(time.RFC3339Nano),
		IngestedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:     event.SourceOTel,
		SchemaV:    event.SchemaVersion,
		Kind:       kind,
		Endpoint: event.Endpoint{
			EndpointID:    c.cfg.EndpointID,
			OS:            runtimeGOOS,
			AgentdVersion: c.version,
		},
		Actor: event.Actor{
			// Prefer OTel's own attribution when present: it comes from Claude
			// Code rather than from our config, so a mismatch is itself a signal.
			UserID: firstNonEmpty(r.Attr("user.id"), c.cfg.UserID),
			OrgID:  firstNonEmpty(r.Attr("organization.id"), c.cfg.OrgID),
		},
		Agent: event.Agent{
			Kind:           "claude-code",
			Version:        r.Attr("app.version"),
			Entrypoint:     r.Attr("app.entrypoint"),
			Model:          r.Attr("model"),
			PermissionMode: r.Attr("permission_mode"),
		},
		Session: event.Session{SessionID: sessionID},
		Policy:  event.Policy{Decision: event.DecisionNone},
	}

	if toolName := r.Attr("tool_name"); toolName != "" {
		t := &event.Tool{Name: toolName, UseID: r.Attr("tool_use_id")}
		if server := r.Attr("mcp_server.name"); server != "" {
			t.MCP = &event.MCP{Server: server, Tool: r.Attr("mcp_tool.name")}
		} else if s, tl, ok := hook.IsMCPTool(toolName); ok {
			t.MCP = &event.MCP{Server: s, Tool: tl}
		}
		e.Tool = t
	}
	return e
}

// OTelStats reports the second stream's state and the discrepancy against the
// hook stream.
type OTelStats struct {
	Records   int64
	ToolCalls int64
	// HookToolCalls is the hook stream's count over the same period.
	HookToolCalls int64
	// LastSeen is when a record last arrived. A stale value with the process
	// alive is the signal that the OTel path specifically has stopped.
	LastSeen time.Time
	// Discrepant is true when exactly one of the two streams is reporting tool
	// calls. Both quiet is an idle endpoint, not a discrepancy.
	Discrepant bool
}

// OTel returns the second-stream statistics.
//
// The comparison is deliberately coarse: "one stream reporting, the other
// silent." It is NOT a per-call reconciliation, and it must not be read as one.
// The two streams see different things — the hook path sees every subscribed
// event while OTel emits on its own schedule and behind content gates — so exact
// counts legitimately differ. Only total silence on one side while the other is
// active is a signal. Tightening this into a ratio threshold needs baseline data
// from M0, not a guess here.
func (c *Collector) OTel() OTelStats {
	otelTools := c.otelToolCalls.Load()
	hookTools := c.hookToolCalls.Load()

	var lastSeen time.Time
	if ns := c.otelLastSeen.Load(); ns > 0 {
		lastSeen = time.Unix(0, ns).UTC()
	}

	return OTelStats{
		Records:       c.otelRecords.Load(),
		ToolCalls:     otelTools,
		HookToolCalls: hookTools,
		LastSeen:      lastSeen,
		Discrepant:    (otelTools == 0) != (hookTools == 0),
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var _ = atomic.Int64{}
