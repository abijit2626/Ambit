package collector

import (
	"fmt"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/filter"
	"github.com/abijit2626/ambit/internal/hook"
	"github.com/abijit2626/ambit/internal/interpose"
)

func wikiListing(server string, tools ...interpose.ToolReport) *interpose.Report {
	return &interpose.Report{SchemaV: interpose.ReportSchemaVersion, Server: server, Trigger: interpose.TriggerToolsList, Tools: tools}
}

func mcpCall(ev, server, tool string) *hook.Payload {
	return &hook.Payload{
		HookEventName: ev, SessionID: "s1", CWD: "/home/dev/src/myrepo",
		ToolName: "mcp__" + server + "__" + tool, ToolUseID: "t_" + tool,
		ToolInput: map[string]any{"page": "x"},
	}
}

func lastTool(t *testing.T, s *memSink, tool string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, m := range siemLines(t, s, "") {
		if m["tool_name"] == tool && (m["kind"] == string(event.KindToolPre) || m["kind"] == string(event.KindToolPost)) {
			found = m
		}
	}
	return found
}

func TestInterposerAnnotationsReachToolCallEvents(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.HandleInterpose(wikiListing("wiki",
		interpose.ToolReport{Tool: "publish", State: event.MCPStateApproved, Annotations: event.Annotations{OpenWorldHint: b(true)}},
		interpose.ToolReport{Tool: "delete_page", State: event.MCPStateApproved, Annotations: event.Annotations{DestructiveHint: b(true)}},
	))

	c.Handle(mcpCall(hook.EvPostToolUse, "wiki", "publish"))
	c.Handle(mcpCall(hook.EvPreToolUse, "wiki", "delete_page"))
	c.Handle(mcpCall(hook.EvPreToolUse, "wiki", "never_listed"))

	if m := lastTool(t, events, "mcp__wiki__publish"); m == nil || m["tool_mcp_openworld_hint"] != true {
		t.Errorf("publish tool_post = %v, want tool_mcp_openworld_hint true (rule 100303 reads it)", m)
	}
	if m := lastTool(t, events, "mcp__wiki__delete_page"); m == nil || m["tool_mcp_destructive_hint"] != true {
		t.Errorf("delete_page tool_pre = %v, want tool_mcp_destructive_hint true", m)
	}
	m := lastTool(t, events, "mcp__wiki__never_listed")
	if m == nil {
		t.Fatal("a call to an unclassified server's tool should still cross")
	}
	for _, k := range []string{"tool_mcp_openworld_hint", "tool_mcp_destructive_hint", "tool_mcp_readonly_hint"} {
		if _, ok := m[k]; ok {
			t.Errorf("never_listed carries %s; a tool the interposer never reported has no annotations", k)
		}
	}
}

func TestDestructiveHintMakesATrustedServersCallCross(t *testing.T) {
	c, events, _ := newTestCollectorWith(t, func(cfg *config.Config) {
		cfg.TrustedMCPServers = []string{"internal-wiki"}
	})
	c.Handle(mcpCall(hook.EvPreToolUse, "internal-wiki", "delete_page"))
	if m := lastTool(t, events, "mcp__internal-wiki__delete_page"); m != nil {
		t.Fatalf("before the interposer reported, a trusted server's call crossed: %v", m)
	}

	c.HandleInterpose(wikiListing("internal-wiki",
		interpose.ToolReport{Tool: "delete_page", State: event.MCPStateApproved, Annotations: event.Annotations{DestructiveHint: b(true)}},
	))
	c.Handle(mcpCall(hook.EvPreToolUse, "internal-wiki", "delete_page"))
	if m := lastTool(t, events, "mcp__internal-wiki__delete_page"); m == nil {
		t.Fatal("a trusted server's destructive tool call did not cross")
	}
	if got := c.Stats().CrossReasons[filter.ReasonMCPRisk]; got != 1 {
		t.Errorf("CrossReasons[%s] = %d, want 1", filter.ReasonMCPRisk, got)
	}
}

func TestAnnotationsFollowTheLatestListing(t *testing.T) {
	c, _, _ := newTestCollector(t)
	c.HandleInterpose(wikiListing("wiki",
		interpose.ToolReport{Tool: "publish", State: event.MCPStateApproved, Annotations: event.Annotations{ReadOnlyHint: b(true)}},
	))
	c.HandleInterpose(wikiListing("wiki",
		interpose.ToolReport{Tool: "publish", State: event.MCPStateDrift, Annotations: event.Annotations{DestructiveHint: b(true)}},
	))
	a, ok := c.annotationsFor("wiki", "publish")
	if !ok || a.DestructiveHint == nil || !*a.DestructiveHint || a.ReadOnlyHint != nil {
		t.Errorf("annotations = %+v, want the drifted listing's: a rug pull that turns a tool destructive must show", a)
	}

	c.HandleInterpose(wikiListing("wiki", interpose.ToolReport{Tool: "publish", State: event.MCPStateRemoved}))
	if _, ok := c.annotationsFor("wiki", "publish"); ok {
		t.Error("a removed tool kept its annotations")
	}
}

func TestAnnotationsAreKeyedByServerAndTool(t *testing.T) {
	c, _, _ := newTestCollector(t)
	c.HandleInterpose(wikiListing("wiki",
		interpose.ToolReport{Tool: "publish", State: event.MCPStateApproved, Annotations: event.Annotations{OpenWorldHint: b(true)}},
	))
	if _, ok := c.annotationsFor("other", "publish"); ok {
		t.Error("another server's tool of the same name got wiki's annotations")
	}
}

func TestAnnotationCacheIsBounded(t *testing.T) {
	c, _, _ := newTestCollector(t)
	tools := make([]interpose.ToolReport, maxAnnotatedTools+10)
	for i := range tools {
		tools[i] = interpose.ToolReport{Tool: fmt.Sprintf("t%d", i), State: event.MCPStateNew}
	}
	c.HandleInterpose(wikiListing("wiki", tools...))
	if n := len(c.ann.byTool); n != maxAnnotatedTools {
		t.Errorf("cache holds %d tools, want the bound %d", n, maxAnnotatedTools)
	}
	if _, ok := c.annotationsFor("wiki", "t0"); !ok {
		t.Error("a tool inside the bound was not cached")
	}
}
