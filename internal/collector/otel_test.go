package collector

import (
	"testing"
	"time"

	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/otlp"
)

func rec(name string, attrs map[string]string) otlp.Record {
	return otlp.Record{Signal: otlp.SignalLogs, Name: name, TS: time.Now().UTC(), Attrs: attrs}
}

// TestOTelGoesToSpoolOnly is the boundary that matters: the OTel stream is
// content-rich and high-volume, and pushing it at the indexer is the firehose the
// filter exists to prevent.
func TestOTelGoesToSpoolOnly(t *testing.T) {
	c, events, traj := newTestCollector(t)
	c.HandleOTel([]otlp.Record{
		rec("claude_code.tool_decision", map[string]string{"session.id": "s1", "tool_name": "Bash", "tool_use_id": "t1"}),
		rec("claude_code.tool_result", map[string]string{"session.id": "s1", "tool_name": "Read"}),
	})
	if traj.count() != 2 {
		t.Errorf("spool got %d OTel events, want 2", traj.count())
	}
	if events.count() != 0 {
		t.Errorf("SIEM sink got %d OTel events, want 0: OTel never crosses to Wazuh", events.count())
	}
}

func TestOTelRecordsCarrySourceAndAttribution(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.HandleOTel([]otlp.Record{rec("claude_code.tool_decision", map[string]string{
		"session.id":      "s1",
		"tool_name":       "Bash",
		"tool_use_id":     "t1",
		"user.id":         "u_from_otel",
		"organization.id": "o_from_otel",
		"app.entrypoint":  "cli",
		"app.version":     "2.1.271",
	})})

	m := traj.decode(t, 0)
	if m["source"] != "otel" {
		t.Errorf("source = %v, want otel", m["source"])
	}
	actor := m["actor"].(map[string]any)
	// OTel's own attribution wins over our config: it comes from Claude Code, so
	// a mismatch between the two is itself worth seeing.
	if actor["user_id"] != "u_from_otel" || actor["org_id"] != "o_from_otel" {
		t.Errorf("actor = %v, want OTel's attribution to win", actor)
	}
	agent := m["agent"].(map[string]any)
	if agent["entrypoint"] != "cli" {
		t.Errorf("entrypoint = %v", agent["entrypoint"])
	}
}

func TestOTelMCPAttribution(t *testing.T) {
	c, _, traj := newTestCollector(t)
	// Explicit MCP attributes.
	c.HandleOTel([]otlp.Record{rec("claude_code.tool_result", map[string]string{
		"session.id": "s1", "tool_name": "mcp__github__create_issue",
		"mcp_server.name": "github", "mcp_tool.name": "create_issue",
	})})
	tool := traj.decode(t, 0)["tool"].(map[string]any)
	mcp := tool["mcp"].(map[string]any)
	if mcp["server"] != "github" || mcp["tool"] != "create_issue" {
		t.Errorf("mcp = %v", mcp)
	}

	// Falling back to parsing the tool name, for when the attributes are
	// redacted — the docs note MCP names are replaced with "custom" unless
	// OTEL_LOG_TOOL_DETAILS is set, so this path is the common one.
	c2, _, traj2 := newTestCollector(t)
	c2.HandleOTel([]otlp.Record{rec("claude_code.tool_result", map[string]string{
		"session.id": "s1", "tool_name": "mcp__jira__create",
	})})
	tool2 := traj2.decode(t, 0)["tool"].(map[string]any)
	mcp2 := tool2["mcp"].(map[string]any)
	if mcp2["server"] != "jira" {
		t.Errorf("mcp server from tool name = %v, want jira", mcp2["server"])
	}
}

func TestOTelUnmodelledEventIsStillSpooled(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.HandleOTel([]otlp.Record{rec("claude_code.something_new", map[string]string{"session.id": "s1"})})
	if traj.count() != 1 {
		t.Error("an unmodelled OTel event must still be spooled: a vanished record is a blind spot in the corroborating stream")
	}
}

// TestStreamDiscrepancy covers D7's finer half. Both streams quiet is an idle
// endpoint; exactly one quiet while the other reports is the signal.
func TestStreamDiscrepancy(t *testing.T) {
	t.Run("both quiet is not discrepant", func(t *testing.T) {
		c, _, _ := newTestCollector(t)
		if c.OTel().Discrepant {
			t.Error("an idle endpoint must not report a discrepancy")
		}
	})

	t.Run("hook only is discrepant", func(t *testing.T) {
		c, _, _ := newTestCollector(t)
		c.Handle(&hook.Payload{
			HookEventName: hook.EvPreToolUse, SessionID: "s1",
			ToolName: "Read", ToolInput: map[string]any{"file_path": "/home/dev/src/myrepo/f.go"},
		})
		st := c.OTel()
		if !st.Discrepant {
			t.Error("hook stream active with OTel silent should be discrepant: the OTel path has stopped")
		}
		if st.HookToolCalls != 1 {
			t.Errorf("HookToolCalls = %d, want 1", st.HookToolCalls)
		}
	})

	t.Run("otel only is discrepant", func(t *testing.T) {
		c, _, _ := newTestCollector(t)
		c.HandleOTel([]otlp.Record{rec("claude_code.tool_decision", map[string]string{"session.id": "s1", "tool_name": "Bash"})})
		if !c.OTel().Discrepant {
			t.Error("OTel active with the hook stream silent should be discrepant: the hook is not installed or ambitd's endpoint is unreachable")
		}
	})

	t.Run("both active is not discrepant", func(t *testing.T) {
		c, _, _ := newTestCollector(t)
		c.Handle(&hook.Payload{
			HookEventName: hook.EvPreToolUse, SessionID: "s1",
			ToolName: "Read", ToolInput: map[string]any{"file_path": "/home/dev/src/myrepo/f.go"},
		})
		c.HandleOTel([]otlp.Record{rec("claude_code.tool_decision", map[string]string{"session.id": "s1", "tool_name": "Read"})})
		st := c.OTel()
		if st.Discrepant {
			t.Error("both streams reporting must not be discrepant even when counts differ")
		}
		// Counts legitimately differ between the streams; the comparison is
		// deliberately "one silent", not a ratio.
		if st.ToolCalls == 0 || st.HookToolCalls == 0 {
			t.Errorf("both counters should be non-zero: %+v", st)
		}
	})
}

func TestOTelLastSeen(t *testing.T) {
	c, _, _ := newTestCollector(t)
	if !c.OTel().LastSeen.IsZero() {
		t.Error("LastSeen should be zero before any record arrives")
	}
	before := time.Now().UTC()
	c.HandleOTel([]otlp.Record{rec("claude_code.tool_decision", map[string]string{"session.id": "s1"})})
	if ls := c.OTel().LastSeen; ls.Before(before.Add(-time.Second)) {
		t.Errorf("LastSeen = %v, want a fresh timestamp", ls)
	}
}

func TestOTelEmptyBatchIsSafe(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.HandleOTel(nil)
	c.HandleOTel([]otlp.Record{})
	if traj.count() != 0 {
		t.Error("an empty batch should produce nothing")
	}
}

func TestOTelSummaryRecordsAreSpooled(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.HandleOTel([]otlp.Record{
		{Signal: otlp.SignalMetrics, Name: "otlp.metrics", TS: time.Now().UTC(), Attrs: map[string]string{"bytes": "512"}},
	})
	if traj.count() != 1 {
		t.Error("a metrics summary record should be spooled so the stream's liveness is visible")
	}
	if c.OTel().ToolCalls != 0 {
		t.Error("a metrics summary must not count as a tool call")
	}
}
