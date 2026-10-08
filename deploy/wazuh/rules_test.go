package wazuh

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/event"
)

const (
	rulesGlob    = "rules/*.xml"
	fixturesPath = "fixtures/events.sample.jsonl"
	runbooksDir  = "runbooks"

	fieldBudget = 55

	groupPendingEmitter = "ambit_pending_emitter"
	groupWazuhSourced   = "ambit_wazuh_sourced"
)

var allocated = map[string][][2]int{
	"ambit_agent_rules.xml":      {{100200, 100229}},
	"ambit_mcp_rules.xml":        {{100230, 100249}},
	"ambit_integrity_rules.xml":  {{100250, 100279}},
	"ambit_provenance_rules.xml": {{100280, 100299}},
	"ambit_egress_rules.xml":     {{100300, 100309}},
	"ambit_telemetry_rules.xml":  {{100310, 100319}},
	"ambit_gate_rules.xml":       {{100320, 100329}},
}

var externalParents = map[int]string{
	550:   "syscheck: integrity checksum changed",
	553:   "syscheck: file deleted",
	554:   "syscheck: file added",
	19007: "sca: policy check failed",
}

type ruleFile struct {
	XMLName xml.Name `xml:"group"`
	Name    string   `xml:"name,attr"`
	Rules   []rule   `xml:"rule"`
}

type rule struct {
	ID          int     `xml:"id,attr"`
	Level       int     `xml:"level,attr"`
	Frequency   int     `xml:"frequency,attr"`
	Timeframe   int     `xml:"timeframe,attr"`
	Ignore      int     `xml:"ignore,attr"`
	DecodedAs   string  `xml:"decoded_as"`
	IfSID       string  `xml:"if_sid"`
	IfMatchedSI string  `xml:"if_matched_sid"`
	SameField   string  `xml:"same_field"`
	Description string  `xml:"description"`
	Groups      string  `xml:"group"`
	Fields      []field `xml:"field"`
	Mitre       struct {
		IDs []string `xml:"id"`
	} `xml:"mitre"`
	file string
}

type field struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Pattern string `xml:",chardata"`
}

func (r rule) isCorrelation() bool { return r.IfMatchedSI != "" }

func (r rule) hasGroup(name string) bool { return strings.Contains(r.Groups, name) }

func (r rule) parentIDs(t *testing.T) []int {
	t.Helper()
	return parseIDList(t, r.IfSID)
}

func parseIDList(t *testing.T, raw string) []int {
	t.Helper()
	var out []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var id int
		if _, err := fmt.Sscanf(part, "%d", &id); err != nil {
			t.Errorf("unparseable rule id %q in %q", part, raw)
			continue
		}
		out = append(out, id)
	}
	return out
}

func readsExternalEvent(r rule, byID map[int]rule, t *testing.T) bool {
	t.Helper()
	return readsExternalDepth(r, byID, t, 0)
}

func readsExternalDepth(r rule, byID map[int]rule, t *testing.T, depth int) bool {
	t.Helper()
	if depth > 8 {
		t.Errorf("rule %d: parent chain deeper than 8, or a cycle", r.ID)
		return false
	}
	for _, raw := range []string{r.IfSID, r.IfMatchedSI} {
		for _, id := range parseIDList(t, raw) {
			if _, ok := externalParents[id]; ok {
				return true
			}
			if parent, ok := byID[id]; ok && readsExternalDepth(parent, byID, t, depth+1) {
				return true
			}
		}
	}
	return false
}

func loadRules(t *testing.T) []rule {
	t.Helper()
	paths, err := filepath.Glob(rulesGlob)
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no rule files matched %s", rulesGlob)
	}
	var out []rule
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var rf ruleFile
		if err := xml.Unmarshal(raw, &rf); err != nil {
			t.Fatalf("%s is not parseable XML: %v", p, err)
		}
		if !strings.HasPrefix(rf.Name, "ambit") {
			t.Errorf("%s: group name %q should start with ambit so the whole ruleset is addressable as one group", p, rf.Name)
		}
		for _, r := range rf.Rules {
			r.file = p
			out = append(out, r)
		}
	}
	return out
}

func loadFixtures(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures: %v (regenerate with: make fixtures)", err)
	}
	var out []map[string]any
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("fixture line %d is not valid JSON: %v", i+1, err)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		t.Fatal("no fixtures")
	}
	return out
}

func schemaFields() (all map[string]bool, arrays map[string]bool) {
	all, arrays = map[string]bool{}, map[string]bool{}
	st := reflect.TypeOf(event.SIEMEvent{})
	for i := 0; i < st.NumField(); i++ {
		tag := st.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		all[name] = true
		ft := st.Field(i).Type
		if ft.Kind() == reflect.Slice {
			arrays[name] = true
		}
	}

	for _, extra := range []string{
		"agent.name", "agent.id", "agent.ip",
		"sca.policy_id", "sca.check.id", "sca.check.title", "sca.check.result",

		"file", "syscheck.path", "syscheck.audit.process.name", "syscheck.uname_after",
		"full_log", "decoder.name",
	} {
		all[extra] = true
	}
	return all, arrays
}

func TestRuleIDsAreUniqueAndInRange(t *testing.T) {
	seen := map[int]string{}
	files := map[string]bool{}
	for _, r := range loadRules(t) {
		base := filepath.Base(r.file)
		files[base] = true
		if prev, dup := seen[r.ID]; dup {
			t.Errorf("rule id %d appears twice (%s and %s); Wazuh refuses a ruleset with duplicate ids at manager start", r.ID, prev, r.file)
		}
		seen[r.ID] = r.file

		ranges, known := allocated[base]
		if !known {
			t.Errorf("%s has no allocated ID range; add one to the map in this test and to the map in ambit_mcp_rules.xml", base)
			continue
		}
		var ok bool
		for _, rg := range ranges {
			if r.ID >= rg[0] && r.ID <= rg[1] {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("rule %d is in %s, whose allocated ranges are %v", r.ID, base, ranges)
		}
	}

	for base := range allocated {
		if !files[base] {
			t.Errorf("the allocation map names %s but no such rule file was loaded", base)
		}
	}
}

func TestEveryRuleIsWellFormed(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	runbookRE := regexp.MustCompile(`runbook_[A-Za-z]+\d+`)
	for _, r := range rules {
		name := fmt.Sprintf("rule_%d", r.ID)
		t.Run(name, func(t *testing.T) {
			if strings.TrimSpace(r.Description) == "" {
				t.Error("no description: an alert with no description is untriageable")
			}
			if r.Level < 0 || r.Level > 16 {
				t.Errorf("level %d is outside 0-16", r.Level)
			}

			if r.Level > 0 {
				if !runbookRE.MatchString(r.Groups) {
					t.Errorf("groups %q name no runbook; every alerting rule carries a runbook group (runbook_Dn, runbook_R2) per docs/03-detection.md", r.Groups)
				}
				if len(r.Mitre.IDs) == 0 {
					t.Error("no MITRE technique: external firms expect a technique id on every alert")
				}
			}
			if r.Level == 0 && r.DecodedAs == "" && r.IfSID == "" {
				t.Error("a level-0 rule that matches nothing and chains from nothing is dead")
			}

			for _, raw := range []string{r.IfSID, r.IfMatchedSI} {
				for _, id := range parseIDList(t, raw) {
					_, ours := byID[id]
					_, external := externalParents[id]
					if !ours && !external {
						t.Errorf("parent rule %d is neither one of ours nor a known Wazuh parent; the rule would never fire", id)
					}
				}
			}

			external := readsExternalEvent(r, byID, t)
			if external && !r.hasGroup(groupWazuhSourced) {
				t.Errorf("reads a Wazuh-owned event but does not declare %s", groupWazuhSourced)
			}
			if r.hasGroup(groupWazuhSourced) && !external {
				t.Errorf("declares %s but reads no Wazuh-owned event", groupWazuhSourced)
			}
			if r.isCorrelation() {
				if r.Frequency <= 0 || r.Timeframe <= 0 {
					t.Errorf("correlation rule needs frequency and timeframe, got %d/%d", r.Frequency, r.Timeframe)
				}
				if r.SameField == "" {
					t.Error("correlation with no same_field fires on unrelated events across the fleet")
				}
			}
		})
	}
}

func TestRuleFieldsExistInTheSchema(t *testing.T) {
	all, _ := schemaFields()
	for _, r := range loadRules(t) {
		for _, f := range r.Fields {
			if !all[f.Name] {
				t.Errorf("rule %d matches field %q, which is not in the flattened schema; the rule would never fire", r.ID, f.Name)
			}
		}
		if r.SameField != "" && !all[r.SameField] {
			t.Errorf("rule %d correlates on same_field %q, which is not in the flattened schema", r.ID, r.SameField)
		}
	}
}

func TestDescriptionInterpolationsExist(t *testing.T) {
	all, _ := schemaFields()
	interp := regexp.MustCompile(`\$\(([^)]+)\)`)
	for _, r := range loadRules(t) {
		for _, m := range interp.FindAllStringSubmatch(r.Description, -1) {
			if !all[m[1]] {
				t.Errorf("rule %d interpolates $(%s), which is not in the flattened schema; the alert would show the literal text", r.ID, m[1])
			}
		}
	}
}

func TestArrayFieldRulesUseUnanchoredLiterals(t *testing.T) {
	_, arrays := schemaFields()
	for _, r := range loadRules(t) {
		for _, f := range r.Fields {
			if !arrays[f.Name] {
				continue
			}
			pattern := strings.TrimSpace(f.Pattern)
			if strings.HasPrefix(pattern, "^") || strings.HasSuffix(pattern, "$") {
				t.Errorf("rule %d anchors a pattern (%q) against array field %q; anchoring depends on unverified decoder behavior for multi-valued fields",
					r.ID, pattern, f.Name)
			}
		}
	}
}

func matches(r rule, ev map[string]any, byID map[int]rule) (bool, error) {

	if r.isCorrelation() {
		return false, fmt.Errorf("rule %d is a correlation rule; matching is not modelled", r.ID)
	}
	if r.DecodedAs == "json" {
		if _, ok := ev["schema_v"]; !ok {
			return false, nil
		}
	}
	if r.IfSID != "" {
		var id int
		if _, err := fmt.Sscanf(strings.Split(r.IfSID, ",")[0], "%d", &id); err != nil {
			return false, err
		}
		if _, external := externalParents[id]; external {

			return false, fmt.Errorf("rule %d reads a Wazuh-internal alert; matching is not modelled", r.ID)
		}
		parent, ok := byID[id]
		if !ok {
			return false, fmt.Errorf("rule %d: parent %d missing", r.ID, id)
		}
		ok, err := matches(parent, ev, byID)
		if err != nil || !ok {
			return false, err
		}
	}
	for _, f := range r.Fields {
		raw, present := ev[f.Name]
		if !present {
			return false, nil
		}
		value := renderValue(raw)
		pattern := strings.TrimSpace(f.Pattern)
		if pattern == `\.+` {

			if value == "" {
				return false, nil
			}
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("rule %d: field %s pattern %q does not compile: %w", r.ID, f.Name, pattern, err)
		}
		if !re.MatchString(value) {
			return false, nil
		}
	}
	return true, nil
}

func renderValue(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			parts = append(parts, renderValue(e))
		}
		return strings.Join(parts, ",")
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func TestEveryRuleMatchesAFixture(t *testing.T) {
	rules := loadRules(t)
	fixtures := loadFixtures(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	for _, r := range rules {
		t.Run(fmt.Sprintf("rule_%d", r.ID), func(t *testing.T) {

			if r.isCorrelation() {
				t.Skip("correlation rule: parent coverage is asserted separately")
			}
			if r.hasGroup(groupWazuhSourced) {
				t.Skip("reads a Wazuh-internal alert: only wazuh-logtest can check it")
			}
			if r.hasGroup(groupPendingEmitter) {
				t.Skip("pending emitter: asserted to match nothing by TestPendingRulesMatchNothingYet")
			}
			var hits int
			for i, ev := range fixtures {
				ok, err := matches(r, ev, byID)
				if err != nil {
					t.Fatalf("fixture %d: %v", i+1, err)
				}
				if ok {
					hits++
				}
			}
			if hits == 0 {
				t.Errorf("rule %d (%s) matches no fixture; regenerate fixtures with `make fixtures` or fix the rule", r.ID, strings.TrimSpace(r.Description))
			}
			t.Logf("rule %d matched %d/%d fixtures", r.ID, hits, len(fixtures))
		})
	}
}

func TestSummaryAndPerToolEventsAreDistinguishable(t *testing.T) {
	var summaries, perTool int
	for i, ev := range loadFixtures(t) {
		if ev["kind"] != string(event.KindMCPList) {
			continue
		}
		_, hasCount := ev["mcp_tool_count"]
		_, hasState := ev["mcp_baseline_state"]
		if hasCount && hasState {
			t.Errorf("fixture %d carries both mcp_tool_count and mcp_baseline_state; the rules cannot tell a listing roll-up from a per-tool finding", i+1)
		}
		switch {
		case hasCount:
			summaries++
			if _, hasTool := ev["tool_mcp_tool"]; hasTool {
				t.Errorf("fixture %d is a per-server summary but names a tool", i+1)
			}
		case hasState:
			perTool++
			if _, hasTool := ev["tool_mcp_tool"]; !hasTool {
				t.Errorf("fixture %d is a per-tool verdict but names no tool", i+1)
			}
		}
	}
	if summaries == 0 || perTool == 0 {
		t.Errorf("fixtures need both shapes: %d summaries, %d per-tool", summaries, perTool)
	}
}

func TestFixturesStayInsideTheFieldBudget(t *testing.T) {
	for i, ev := range loadFixtures(t) {
		if len(ev) > fieldBudget {
			t.Errorf("fixture %d has %d fields, budget is %d: an event this wide risks the decoder rejecting it, which is silent detection loss", i+1, len(ev), fieldBudget)
		}
	}
}

func TestFixturesCarryNoCleartextSecrets(t *testing.T) {
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}

	for _, banned := range []string{
		"/home/dev", ".ssh", "id_ed25519", "id_rsa", ".aws",
		"Ignore all previous", "exfil.attacker.test", "billing",
	} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("fixtures contain %q in cleartext; the SIEM-bound sink must not carry it, so neither may a fixture generated from it", banned)
		}
	}
}

func TestEveryReferencedRunbookExists(t *testing.T) {

	runbookRE := regexp.MustCompile(`runbook_([A-Za-z]+\d+)`)
	wanted := map[string]int{}
	for _, r := range loadRules(t) {
		for _, m := range runbookRE.FindAllStringSubmatch(r.Groups, -1) {
			wanted[m[1]] = r.ID
		}
	}
	if len(wanted) == 0 {
		t.Fatal("no rule names a runbook")
	}
	for detector, ruleID := range wanted {
		matches, err := filepath.Glob(filepath.Join(runbooksDir, detector+"-*.md"))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		if len(matches) == 0 {
			t.Errorf("rule %d names runbook_%s but no %s/%s-*.md exists; an alert whose runbook is missing is an alert an external analyst cannot action",
				ruleID, detector, runbooksDir, detector)
		}
	}
}

func TestRunbooksCoverTheRequiredSections(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(runbooksDir, "*.md"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no runbooks yet")
	}
	required := []string{
		"What this alert asserts",
		"What it does not assert",
		"Triage",
		"What requires us",
		"Containment",
		"Escalation",
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		body := string(raw)
		for _, section := range required {
			if !strings.Contains(body, section) {
				t.Errorf("%s has no %q section; docs/03-detection.md requires all six, in order", p, section)
			}
		}
	}
}

func TestOrdinaryDriftDoesNotPage(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	var checked int
	for i, ev := range loadFixtures(t) {
		if ev["mcp_baseline_state"] != event.MCPStateDrift {
			continue
		}
		if _, hasFindings := ev["mcp_scan_classes"]; hasFindings {
			continue
		}
		checked++

		ok, err := matches(byID[100234], ev, byID)
		if err != nil {
			t.Fatalf("fixture %d: %v", i+1, err)
		}
		if !ok {
			t.Errorf("fixture %d is a drift event but rule 100234 does not match it", i+1)
		}

		for _, r := range rules {
			if !strings.Contains(r.Groups, "ambit_d5") || r.isCorrelation() {
				continue
			}
			ok, err := matches(r, ev, byID)
			if err != nil {
				t.Fatalf("fixture %d, rule %d: %v", i+1, r.ID, err)
			}
			if ok {
				t.Errorf("rule %d (level %d, %q) matches an ordinary description change with no findings; a benign upgrade would page",
					r.ID, r.Level, strings.TrimSpace(r.Description))
			}
		}
	}
	if checked == 0 {
		t.Error("no drift-without-findings fixture: the false-positive control has nothing to test against; regenerate with `make fixtures`")
	}
}

func TestPendingRulesMatchNothingYet(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	fixtures := loadFixtures(t)

	var pending int
	for _, r := range rules {
		if !r.hasGroup(groupPendingEmitter) || r.isCorrelation() || r.hasGroup(groupWazuhSourced) {
			continue
		}
		pending++
		for i, ev := range fixtures {
			if isSynthetic(ev) {
				continue
			}
			ok, err := matches(r, ev, byID)
			if err != nil {
				t.Fatalf("rule %d, fixture %d: %v", r.ID, i+1, err)
			}
			if ok {
				t.Errorf("rule %d is marked %s but matches real fixture %d; the emitter exists, so remove the marker",
					r.ID, groupPendingEmitter, i+1)
			}
		}
	}
	if pending == 0 {
		t.Log("no pending-emitter rules; delete this test when the last marker goes")
	}
}

func isSynthetic(ev map[string]any) bool {
	id, _ := ev["event_id"].(string)
	return strings.HasPrefix(id, "01JSYNTH") || ev["kind"] == "sink_gap"
}

func TestRulesStayQuietWhereTheyShould(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	cases := []struct {
		name string
		rule int

		pick func(map[string]any) bool
		why  string
	}{
		{
			name: "D8 does not fire on a trusted instruction file",
			rule: 100290,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "instructions_loaded" && ev["config_trusted"] == true
			},
			why: "a CLAUDE.md from a trusted repo path is every session's normal startup",
		},
		{
			name: "D8's untrusted-zone rule does not fire on a home-zone file",
			rule: 100291,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "instructions_loaded" && ev["config_zone"] == "home"
			},
			why: "the zone escalation is for dependency and download paths, not the user's own home",
		},
		{
			name: "D1's credential rule does not fire outside bypassPermissions",
			rule: 100201,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "tool_pre" && ev["permission_mode"] == "default"
			},
			why: "a credential read in a prompting session is D2's business, not D1's",
		},
		{
			name: "D2's sweep base does not fire on a credential write",
			rule: 100210,
			pick: func(ev map[string]any) bool {
				return ev["path_zone"] == "credential" && ev["path_op"] == "write"
			},
			why: "the read threshold and the write alert are separate detectors of separate things",
		},
		{
			name: "D7 does not fire on a healthy heartbeat",
			rule: 100311,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "ambitd_health" && ev["health_status"] == "ok"
			},
			why: "every endpoint heartbeats on a timer; alerting on a healthy one is pure volume",
		},
		{
			name: "the provenance-edge rule does not fire on a network command with no edge",
			rule: 100283,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "tool_pre" && ev["bash_command_class"] == "network" && ev["prov_edge_count"] == nil
			},
			why: "most outbound commands derive from nothing the session ingested; paging on them would make the rule noise",
		},
		{
			name: "the composite gate rule does not fire on a would-be block with no edge",
			rule: 100323,
			pick: func(ev map[string]any) bool {
				return ev["policy_decision"] == "deny" && ev["prov_edge_count"] == nil
			},
			why: "the page condition is the block AND the edge; a deny alone is level 8, not 13",
		},
		{
			name: "the gate's deny rule does not fire on an ordinary tool call",
			rule: 100320,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "tool_pre" && ev["policy_decision"] == nil
			},
			why: "a tool call the gate had no opinion on is the overwhelming majority of the stream",
		},
		{
			name: "D6's system-zone rule does not fire on a home-zone config change",
			rule: 100253,
			pick: func(ev map[string]any) bool {
				return ev["kind"] == "config_change" && ev["config_zone"] == "home"
			},
			why: "a developer editing their own settings is not a managed-settings change",
		},
	}

	fixtures := loadFixtures(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, ok := byID[c.rule]
			if !ok {
				t.Fatalf("rule %d not found", c.rule)
			}
			var tested int
			for i, ev := range fixtures {
				if !c.pick(ev) {
					continue
				}
				tested++
				got, err := matches(r, ev, byID)
				if err != nil {
					t.Fatalf("fixture %d: %v", i+1, err)
				}
				if got {
					t.Errorf("rule %d matches fixture %d, which it should not: %s", c.rule, i+1, c.why)
				}
			}
			if tested == 0 {
				t.Skipf("no fixture of this shape; regenerate with `make fixtures` or drop the case")
			}
		})
	}
}

func TestProvenanceEdgeRuleHasARealEmitter(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	r, ok := byID[100283]
	if !ok {
		t.Fatal("rule 100283 not found")
	}
	if r.hasGroup(groupPendingEmitter) {
		t.Errorf("rule 100283 still carries %s, but the provenance engine exists", groupPendingEmitter)
	}

	var generated, synthetic int
	for i, ev := range loadFixtures(t) {
		got, err := matches(r, ev, byID)
		if err != nil {
			t.Fatalf("fixture %d: %v", i+1, err)
		}
		if !got {
			continue
		}
		if isSynthetic(ev) {
			synthetic++
			continue
		}
		generated++

		if from, _ := ev["prov_edge_from"].(string); from == "" {
			t.Errorf("generated fixture %d matched but carries no prov_edge_from", i+1)
		}
		if _, ok := ev["prov_edge_confidence"].(float64); !ok {
			t.Errorf("generated fixture %d matched but carries no prov_edge_confidence", i+1)
		}
	}
	if generated == 0 {
		t.Errorf("rule 100283 matches no generated fixture (%d synthetic): ambitd is not producing provenance edges, "+
			"or the fixtures are stale; run `make fixtures`", synthetic)
	}
}

func TestGateRulesHaveARealEmitter(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	fixtures := loadFixtures(t)
	for _, id := range []int{100320, 100321, 100322, 100323} {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("rule %d not found", id)
		}
		generated := 0
		for i, ev := range fixtures {
			if isSynthetic(ev) {
				continue
			}
			got, err := matches(r, ev, byID)
			if err != nil {
				t.Fatalf("rule %d, fixture %d: %v", id, i+1, err)
			}
			if got {
				generated++
				if ev["policy_shadow"] != true {
					t.Errorf("rule %d matched fixture %d with policy_shadow %v; every gate verdict is shadow in M2", id, i+1, ev["policy_shadow"])
				}
			}
		}
		if generated == 0 {
			t.Errorf("rule %d matches no generated fixture; the gate is not emitting what it reads, or the fixtures are stale (`make fixtures`)", id)
		}
	}
}

func TestDeployArtifactsAreWellFormed(t *testing.T) {

	root := ".."
	var xmlFiles, jsonFiles int

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".xml":
			xmlFiles++
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("%s: %v", path, readErr)
				return nil
			}

			dec := xml.NewDecoder(strings.NewReader(string(raw)))
			for {
				_, tokErr := dec.Token()
				if tokErr != nil {
					if tokErr.Error() == "EOF" {
						break
					}
					t.Errorf("%s is not well-formed XML: %v\n  (a double hyphen inside an XML comment is the usual cause, and Wazuh refuses the file)", path, tokErr)
					break
				}
			}
		case ".json":
			jsonFiles++
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("%s: %v", path, readErr)
				return nil
			}
			var v any
			if jsonErr := json.Unmarshal(raw, &v); jsonErr != nil {
				t.Errorf("%s is not valid JSON: %v", path, jsonErr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if xmlFiles == 0 || jsonFiles == 0 {
		t.Errorf("found %d XML and %d JSON files under %s; expected both", xmlFiles, jsonFiles, root)
	}
	t.Logf("parsed %d XML and %d JSON deploy artifacts", xmlFiles, jsonFiles)
}
