package collector

import (
	"time"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/interpose"
)

// HandleInterpose turns one interposer report into mcp_list events.
//
// The division of labour is the point: mcp-interpose observes and compares, and
// ambitd decides identity, trust and what crosses. Specifically, ambitd — not the
// interposer — assigns the event id, the endpoint and actor identity, the trust
// label from operator configuration, and the Wazuh verdict. The interposer runs as
// the developer, as a child of the agent process, and giving a process inside that
// blast radius any of those would defeat the point of the split. See
// docs/08-mcp-interpose-decision.md.
//
// One report becomes a per-server summary event plus one event per tool. The
// summary always crosses to Wazuh; the per-tool events cross only when they say
// something. internal/filter has the reasoning.
func (c *Collector) HandleInterpose(rep *interpose.Report) {
	if rep == nil || rep.Server == "" {
		return
	}
	c.interposeReports.Add(1)

	// A degraded interposer is reported through the existing health path rather
	// than a new one. "The baseline store could not be written" means D4 is blind
	// on this endpoint, which is the same class of fact as a collection path going
	// silent, and D7's rules already read ambitd_health.
	if rep.Degraded {
		c.log.Warn("interposer degraded",
			"server", rep.Server, "reason", rep.DegradedReason, "trigger", rep.Trigger)
		c.emitInterposeHealth(rep)
	}

	trust := ""
	if c.cfg.TrustedMCPSet()[rep.Server] {
		trust = "internal"
	}
	st := c.interposeSession(rep)

	summary := c.interposeEvent(rep, st)
	summary.Tool = &event.Tool{
		MCP: &event.MCP{
			Server:        rep.Server,
			Trust:         trust,
			BaselineState: rep.Worst,
			ToolCount:     rep.Counts.Tools,
			NewCount:      rep.Counts.New,
			DriftCount:    rep.Counts.Drift,
			RemovedCount:  rep.Counts.Removed,
			Trigger:       rep.Trigger,
			Approved:      boolPtr(rep.Approved),
			Complete:      boolPtr(rep.Complete),
			ServerVersion: rep.ServerInfo.Version,
			CallsObserved: rep.CallsObserved,
		},
	}
	c.handled.Add(1)
	c.interposeEvents.Add(1)
	c.emit(summary)

	for _, t := range rep.Tools {
		e := c.interposeEvent(rep, st)
		e.Tool = &event.Tool{
			// The name Claude Code would use for this tool. Reconstructing it is
			// what makes tool identity survive interposition: a Wazuh rule can
			// correlate this listing against the calls that follow, and a
			// managed-settings permission rule still names the same tool. The
			// gateways evaluated in docs/08 broke exactly this.
			Name: mcpToolName(rep.Server, t.Tool),
			MCP: &event.MCP{
				Server:           rep.Server,
				Tool:             t.Tool,
				Trust:            trust,
				MetadataHash:     t.MetadataHash,
				PrevMetadataHash: t.PrevHash,
				BaselineState:    t.State,
				ChangedFields:    t.ChangedFields,
				ScanClasses:      t.ScanClasses,
				ScanRules:        t.ScanRules,
				Trigger:          rep.Trigger,
				Approved:         boolPtr(rep.Approved),
				Complete:         boolPtr(rep.Complete),
				ServerVersion:    rep.ServerInfo.Version,
				// Annotations are carried exactly as the server stated them, with
				// absent distinct from false, and they may only make policy
				// stricter. A server claiming readOnlyHint earns no relaxation
				// here or anywhere downstream. See docs/02.
				Annotations: t.Annotations,
			},
		}
		c.handled.Add(1)
		c.interposeEvents.Add(1)
		c.emit(e)
	}
}

// interposeEvent builds the common envelope for an mcp_list event.
func (c *Collector) interposeEvent(rep *interpose.Report, st *sessionState) *event.Event {
	now := time.Now().UTC()
	ts := rep.TS
	if ts == "" {
		ts = now.Format(time.RFC3339Nano)
	}
	e := &event.Event{
		EventID: newEventID(),
		// TS is the interposer's observation time; IngestedAt is ours. Keeping
		// both is what lets an investigation see a report that arrived late.
		TS:         ts,
		IngestedAt: now.Format(time.RFC3339Nano),
		Source:     event.SourceInterpose,
		SchemaV:    event.SchemaVersion,
		Kind:       event.KindMCPList,
		Endpoint: event.Endpoint{
			EndpointID:    c.cfg.EndpointID,
			OS:            runtimeGOOS,
			AmbitdVersion: c.version,
		},
		Actor: event.Actor{UserID: c.cfg.UserID, OrgID: c.cfg.OrgID},
		Agent: event.Agent{
			Kind: "claude-code",
			// The MCP client's self-reported version, which for our purposes is
			// the agent's. A claim, recorded rather than trusted.
			Version: rep.ClientVersion,
		},
		Session: event.Session{
			// Often empty: MCP carries no Claude Code session id and the
			// interposer refuses to invent one. See interpose.Report.SessionID.
			SessionID: rep.SessionID,
			Sequence:  st.next(),
		},
		R2:     st.snapshotR2(),
		Policy: event.Policy{Decision: event.DecisionNone},
	}
	if c.hostname != "" {
		e.Endpoint.HostnameDigest = c.ext.Digest(c.hostname)
	}
	return e
}

// emitInterposeHealth reports a degraded interposer as an ambitd_health event.
func (c *Collector) emitInterposeHealth(rep *interpose.Report) {
	now := time.Now().UTC()
	e := &event.Event{
		EventID:    newEventID(),
		TS:         now.Format(time.RFC3339Nano),
		IngestedAt: now.Format(time.RFC3339Nano),
		Source:     event.SourceInterpose,
		SchemaV:    event.SchemaVersion,
		Kind:       event.KindAmbitdHealth,
		Endpoint: event.Endpoint{
			EndpointID:    c.cfg.EndpointID,
			OS:            runtimeGOOS,
			AmbitdVersion: c.version,
		},
		Actor:  event.Actor{UserID: c.cfg.UserID, OrgID: c.cfg.OrgID},
		Agent:  event.Agent{Kind: "claude-code"},
		Policy: event.Policy{Decision: event.DecisionNone},
		Health: &event.Health{Status: "degraded"},
	}
	c.emit(e)
}

// interposeSession finds or creates the sequence counter for a report.
//
// Reports usually carry no session id, so they are keyed on the server instead.
// The key is prefixed so it can never collide with a real Claude Code session id
// and quietly share a sequence counter with it.
func (c *Collector) interposeSession(rep *interpose.Report) *sessionState {
	key := rep.SessionID
	if key == "" {
		key = "interpose:" + rep.Server
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.sessions[key]
	if !ok {
		st = &sessionState{}
		c.sessions[key] = st
	}
	return st
}

// mcpToolName reconstructs Claude Code's MCP tool name.
func mcpToolName(server, tool string) string {
	if server == "" || tool == "" {
		return ""
	}
	return "mcp__" + server + "__" + tool
}

func boolPtr(v bool) *bool { return &v }
