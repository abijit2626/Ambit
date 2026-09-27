package collector

import (
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/interpose"
	"github.com/abijit2626/ambit/internal/mcp"
)

func b(v bool) *bool { return &v }

func listingReport() *interpose.Report {
	return &interpose.Report{
		SchemaV:       interpose.ReportSchemaVersion,
		Server:        "github",
		Trigger:       interpose.TriggerToolsList,
		ClientVersion: "2.1.271",
		ServerInfo:    mcp.ServerInfo{Name: "github", Version: "1.4.0"},
		Complete:      true,
		Approved:      true,
		Worst:         event.MCPStateDrift,
		CallsObserved: 12,
		Counts:        baseline.Counts{Tools: 2, Drift: 1, Unchanged: 1},
		Tools: []interpose.ToolReport{
			{
				Tool: "create_issue", State: event.MCPStateApproved,
				MetadataHash: "sha256:aaa",
				Annotations:  event.Annotations{ReadOnlyHint: b(false)},
			},
			{
				Tool: "search_code", State: event.MCPStateDrift,
				MetadataHash: "sha256:bbb", PrevHash: "sha256:ccc",
				ChangedFields: []string{"description"},
				ScanClasses:   []string{"hidden_instruction", "sensitive_file_ref"},
				ScanRules:     []string{"hidden.ignore_previous", "sensitive_file.ssh"},
				Annotations:   event.Annotations{OpenWorldHint: b(true)},
			},
		},
	}
}

// TestInterposeReportBecomesEvents covers the split: one report becomes a per-server
// summary plus one event per tool, all of them mcp_list, sourced as interpose.
func TestInterposeReportBecomesEvents(t *testing.T) {
	c, _, traj := newTestCollector(t)
	c.HandleInterpose(listingReport())

	// Spool holds everything: the summary plus both tools.
	if traj.count() != 3 {
		t.Fatalf("spool got %d events, want 3 (summary + 2 tools)", traj.count())
	}
	summary := traj.decode(t, 0)
	if summary["kind"] != string(event.KindMCPList) {
		t.Errorf("kind = %v, want %v", summary["kind"], event.KindMCPList)
	}
	if summary["source"] != string(event.SourceInterpose) {
		t.Errorf("source = %v, want %v", summary["source"], event.SourceInterpose)
	}

	if st := c.Stats(); st.InterposeReports != 1 || st.InterposeEvents != 3 {
		t.Errorf("stats = %+v, want 1 report and 3 events", st)
	}
}

// TestInterposeToolIdentityIsReconstructed is the property the whole per-server
// design exists to protect. A Wazuh rule correlating a listing with the calls that
// follow, and a managed-settings permission rule naming a tool, both depend on this
// exact string.
func TestInterposeToolIdentityIsReconstructed(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.HandleInterpose(listingReport())

	var found bool
	for i := 0; i < events.count(); i++ {
		e := events.decode(t, i)
		if e["tool_mcp_tool"] == "search_code" {
			found = true
			if got := e["tool_name"]; got != "mcp__github__search_code" {
				t.Errorf("tool_name = %v, want mcp__github__search_code", got)
			}
			if got := e["tool_mcp_server"]; got != "github" {
				t.Errorf("tool_mcp_server = %v, want github", got)
			}
		}
	}
	if !found {
		t.Fatal("the drifted tool did not cross to the SIEM sink")
	}
}

// TestApprovedToolsDoNotCrossButDriftDoes is the volume control from docs/04: one
// event per server per session, plus the tools that say something.
func TestApprovedToolsDoNotCrossButDriftDoes(t *testing.T) {
	c, events, traj := newTestCollector(t)
	c.HandleInterpose(listingReport())

	if traj.count() != 3 {
		t.Fatalf("spool got %d events, want 3", traj.count())
	}
	// Summary + the drifted tool. The approved tool with no findings stays local.
	if events.count() != 2 {
		t.Fatalf("SIEM sink got %d events, want 2 (summary + drift):\n%s", events.count(), events.all())
	}
	if strings.Contains(events.all(), "create_issue") {
		t.Error("a tool matching its approved baseline with no findings should not cross")
	}
	if !strings.Contains(traj.all(), "create_issue") {
		t.Error("the approved tool must still be in the spool; that is the investigation corpus")
	}
}

func TestInterposeSummaryCarriesTheInventory(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.HandleInterpose(listingReport())

	summary := events.decode(t, 0)
	if summary["tool_mcp_tool"] != nil {
		t.Errorf("the summary event should name no tool, got %v", summary["tool_mcp_tool"])
	}
	if summary["mcp_baseline_state"] != event.MCPStateDrift {
		t.Errorf("summary state = %v, want the worst finding %q", summary["mcp_baseline_state"], event.MCPStateDrift)
	}
	if summary["mcp_tool_count"] != float64(2) {
		t.Errorf("mcp_tool_count = %v, want 2: the summary is the inventory record", summary["mcp_tool_count"])
	}
	if summary["mcp_trigger"] != interpose.TriggerToolsList {
		t.Errorf("summary trigger = %v", summary["mcp_trigger"])
	}
}

func TestInterposeDriftEventCarriesBothSidesAndClasses(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.HandleInterpose(listingReport())

	var drift map[string]any
	for i := 0; i < events.count(); i++ {
		if e := events.decode(t, i); e["tool_mcp_tool"] == "search_code" {
			drift = e
		}
	}
	if drift == nil {
		t.Fatal("no drift event crossed")
	}
	if drift["mcp_baseline_state"] != event.MCPStateDrift {
		t.Errorf("state = %v", drift["mcp_baseline_state"])
	}
	if drift["tool_mcp_metadata_hash"] != "sha256:bbb" || drift["mcp_prev_metadata_hash"] != "sha256:ccc" {
		t.Errorf("a drift alert needs both sides: %v / %v", drift["tool_mcp_metadata_hash"], drift["mcp_prev_metadata_hash"])
	}
	changed, ok := drift["mcp_changed_fields"].([]any)
	if !ok || len(changed) != 1 || changed[0] != "description" {
		t.Errorf("mcp_changed_fields = %v", drift["mcp_changed_fields"])
	}
	classes, ok := drift["mcp_scan_classes"].([]any)
	if !ok || len(classes) != 2 {
		t.Errorf("mcp_scan_classes = %v", drift["mcp_scan_classes"])
	}
	// Rule ids are for local tuning and must not cross.
	if strings.Contains(events.all(), "hidden.ignore_previous") {
		t.Error("scan rule ids crossed to the SIEM sink; they are local tuning data")
	}
}

// TestInterposeAnnotationsSurviveWithAbsentDistinctFromFalse is requirement 4 from
// docs/02: annotations are carried as stated, and absent never becomes false.
func TestInterposeAnnotationsSurviveWithAbsentDistinctFromFalse(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.HandleInterpose(listingReport())

	var drift map[string]any
	for i := 0; i < events.count(); i++ {
		if e := events.decode(t, i); e["tool_mcp_tool"] == "search_code" {
			drift = e
		}
	}
	if drift == nil {
		t.Fatal("no drift event crossed")
	}
	if drift["tool_mcp_openworld_hint"] != true {
		t.Errorf("openWorldHint true was lost: %v", drift["tool_mcp_openworld_hint"])
	}
	if _, present := drift["tool_mcp_readonly_hint"]; present {
		t.Error("readOnlyHint was absent and must stay absent rather than serialize as false")
	}
	if _, present := drift["tool_mcp_destructive_hint"]; present {
		t.Error("destructiveHint was absent and must stay absent")
	}
}

// TestTrustComesFromConfigurationNotTheServer: the interposer reports what a server
// said; only operator configuration decides trust.
func TestTrustComesFromConfigurationNotTheServer(t *testing.T) {
	c, _, traj := newTestCollector(t)

	untrusted := listingReport()
	c.HandleInterpose(untrusted)
	if got := traj.decode(t, 0)["tool"].(map[string]any)["mcp"].(map[string]any)["trust"]; got != nil {
		t.Errorf("an unconfigured server got trust %v; only configuration grants it", got)
	}

	trusted := listingReport()
	trusted.Server = "internal-wiki" // the one in the test config's trusted list
	c.HandleInterpose(trusted)
	mcpBlock := traj.decode(t, 3)["tool"].(map[string]any)["mcp"].(map[string]any)
	if mcpBlock["trust"] != "internal" {
		t.Errorf("configured server trust = %v, want internal", mcpBlock["trust"])
	}
}

// TestDegradedInterposerReportsHealth: "the baseline store could not be written"
// means D4 is blind on this endpoint, which belongs in the health stream D7 reads.
func TestDegradedInterposerReportsHealth(t *testing.T) {
	c, events, _ := newTestCollector(t)
	rep := listingReport()
	rep.Degraded = true
	rep.DegradedReason = "baseline store unavailable: permission denied"
	c.HandleInterpose(rep)

	health := events.decode(t, 0)
	if health["kind"] != string(event.KindAmbitdHealth) {
		t.Fatalf("first crossing event kind = %v, want %v", health["kind"], event.KindAmbitdHealth)
	}
	if health["health_status"] != "degraded" {
		t.Errorf("health_status = %v, want degraded", health["health_status"])
	}
	// The reason is operational detail and stays out of the SIEM-bound event; it is
	// logged locally instead.
	if strings.Contains(events.all(), "permission denied") {
		t.Error("the degraded reason should not cross; it can name local paths")
	}
}

func TestEmptyAndNilReportsAreIgnored(t *testing.T) {
	c, events, traj := newTestCollector(t)
	c.HandleInterpose(nil)
	c.HandleInterpose(&interpose.Report{SchemaV: interpose.ReportSchemaVersion})
	if traj.count() != 0 || events.count() != 0 {
		t.Errorf("a report with no server produced events: spool=%d siem=%d", traj.count(), events.count())
	}
}

// TestNoServerMetadataTextCrosses is the leak control for this path. Descriptions are
// third-party text held on the endpoint; nothing from them may ride an mcp_list event
// to a SIEM or onward to a monitoring firm.
func TestNoServerMetadataTextCrosses(t *testing.T) {
	c, events, _ := newTestCollector(t)
	rep := listingReport()
	rep.Tools[1].ScanRules = []string{"hidden.ignore_previous"}
	c.HandleInterpose(rep)

	for _, banned := range []string{"Ignore all previous", "id_rsa", "hidden.ignore_previous", "1.4.0"} {
		if strings.Contains(events.all(), banned) {
			t.Errorf("SIEM sink leaked %q:\n%s", banned, events.all())
		}
	}
}
