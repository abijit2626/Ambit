package collector

import (
	"time"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/interpose"
)

func (c *Collector) HandleInterpose(rep *interpose.Report) {
	if rep == nil || rep.Server == "" {
		return
	}
	c.interposeReports.Add(1)
	c.rememberAnnotations(rep)

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
	transport := reportTransport(rep.Transport)

	summary := c.interposeEvent(rep, st)
	summary.Tool = &event.Tool{
		MCP: &event.MCP{
			Server: rep.Server,
			Trust:  trust,

			Worst:         rep.Worst,
			ToolCount:     rep.Counts.Tools,
			NewCount:      rep.Counts.New,
			DriftCount:    rep.Counts.Drift,
			RemovedCount:  rep.Counts.Removed,
			Trigger:       rep.Trigger,
			Approved:      boolPtr(rep.Approved),
			Complete:      boolPtr(rep.Complete),
			ServerVersion: rep.ServerInfo.Version,
			CallsObserved: rep.CallsObserved,
			Transport:     transport,
		},
	}
	c.handled.Add(1)
	c.interposeEvents.Add(1)
	c.emit(summary)

	for _, t := range rep.Tools {
		e := c.interposeEvent(rep, st)
		e.Tool = &event.Tool{

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
				Transport:        transport,

				Annotations: t.Annotations,
			},
		}
		c.handled.Add(1)
		c.interposeEvents.Add(1)
		c.emit(e)
	}
}

// reportTransport keeps a report's transport only if it is one the interposer sends. The report comes
// from a process running as the developer and the value crosses to the SIEM in cleartext, so it must
// not be able to carry arbitrary text.
func reportTransport(t string) string {
	switch t {
	case interpose.TransportStdio, string(interpose.TransportHTTP), string(interpose.TransportSSE):
		return t
	}
	return ""
}

func (c *Collector) interposeEvent(rep *interpose.Report, st *sessionState) *event.Event {
	now := time.Now().UTC()
	ts := rep.TS
	if ts == "" {
		ts = now.Format(time.RFC3339Nano)
	}
	e := &event.Event{
		EventID: newEventID(),

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

			Version: rep.ClientVersion,
		},
		Session: event.Session{

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

func mcpToolName(server, tool string) string {
	if server == "" || tool == "" {
		return ""
	}
	return "mcp__" + server + "__" + tool
}

func boolPtr(v bool) *bool { return &v }
