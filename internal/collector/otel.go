package collector

import (
	"sync/atomic"
	"time"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/otlp"
)

var otelToolEvents = map[string]bool{
	"claude_code.tool_decision": true,
	"claude_code.tool_result":   true,
}

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

		kind = event.KindAmbitdHealth
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
			AmbitdVersion: c.version,
		},
		Actor: event.Actor{

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

type OTelStats struct {
	Records   int64
	ToolCalls int64

	HookToolCalls int64

	LastSeen time.Time

	Discrepant bool
}

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
