// Package wazuh holds no code: it exists so the Wazuh rules, the fixtures they are
// tested against and the runbooks they reference can be validated by `go test ./...`
// like anything else in this repository.
//
// The reason this exists is that a broken Wazuh rule does not fail loudly. It simply
// never matches, and a detector that never fires is indistinguishable from a fleet
// with nothing to report. `wazuh-logtest` is the real check and the README says to run
// it, but it needs a Wazuh install, so it is not run in CI and not run by a contributor
// changing a field name. These tests are what catch that change: they read the
// flattened schema out of internal/event by reflection, so renaming a field breaks the
// build rather than silently retiring a rule.
//
// What these tests do NOT do: implement Wazuh. They model the small subset of matching
// the rules in this directory use — decoded_as json, if_sid chaining, and field regexes
// — well enough to prove each rule can match a real event. Correlation semantics
// (frequency, timeframe, ignore) are checked structurally only. Where the model and
// Wazuh could disagree, the tests assert the rules stay inside the subset where they
// cannot, which is why an unanchored-literal rule on an array field is a test of its
// own.
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

	// fieldBudget mirrors internal/event's per-kind budget. A fixture wider than the
	// events the schema is allowed to produce would be testing something that cannot
	// reach the decoder.
	fieldBudget = 55

	// Groups that exempt a rule from the "must match a real fixture" requirement, for
	// the two reasons a rule can legitimately match nothing today.
	//
	// groupPendingEmitter: the field is in the flattened schema but nothing populates it
	// yet — the policy engine (M3), the provenance engine (M2), goal-drift scoring (M4),
	// or agent_entrypoint, which is specified and has no emitter anywhere. Such a rule
	// must match NOTHING in the real fixtures: if it matches, the emitter exists and the
	// marker is stale, which is worse than missing because it hides a working detector.
	//
	// groupWazuhSourced: the input is a Wazuh-internal alert — a syscheck FIM event or an
	// SCA result — not one of our JSON events. Our fixtures cannot contain one by
	// construction, so wazuh-logtest against a real alert is the only check.
	groupPendingEmitter = "ambit_pending_emitter"
	groupWazuhSourced   = "ambit_wazuh_sourced"
)

// allocated maps each rule file to the ID ranges it may use. The full map with its
// reasoning lives in rules/ambit_mcp_rules.xml; this is the enforced copy.
//
// Wazuh refuses a ruleset with duplicate ids at manager start, so a collision takes the
// whole manager down rather than degrading one detector. That makes the allocation worth
// testing rather than documenting.
var allocated = map[string][][2]int{
	"ambit_agent_rules.xml":      {{100200, 100229}}, // D1, D2, D3
	"ambit_mcp_rules.xml":        {{100230, 100249}}, // D4, D5
	"ambit_integrity_rules.xml":  {{100250, 100279}}, // D6, D11, D12
	"ambit_provenance_rules.xml": {{100280, 100299}}, // D10, D8
	"ambit_egress_rules.xml":     {{100300, 100309}}, // D9
	"ambit_telemetry_rules.xml":  {{100310, 100319}}, // D7
}

// externalParents are rule IDs owned by Wazuh's shipped ruleset, not by us: syscheck FIM
// alerts and SCA results. A rule chaining from one of these is reading an event our
// fixtures cannot contain, so it must declare groupWazuhSourced.
//
// These values are UNVERIFIED against the shipped ruleset (docs/00-sources.md) and are
// listed here so the set is at least explicit: a wrong parent SID does not error, the
// rule simply never fires.
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

// parentIDs parses if_sid, which Wazuh allows as a comma-separated list.
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

// readsExternalEvent reports whether the rule ultimately reads a Wazuh-owned event.
//
// The chain has to be followed rather than only the immediate parent: a correlation over
// an SCA-sourced rule is still SCA-sourced, and its own parent is one of ours.
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

// loadRules reads every rule file in the directory.
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

// schemaFields returns the flattened schema's field names, and which of them are
// arrays, by reflection over event.SIEMEvent. Reflection rather than a hand-kept list
// is the point: a renamed field then fails this test instead of quietly retiring a rule.
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
	// Fields Wazuh itself supplies on an alert rather than the event. Listed rather
	// than pattern-matched so adding one is a decision.
	for _, extra := range []string{
		"agent.name", "agent.id", "agent.ip",
		"sca.policy_id", "sca.check.id", "sca.check.title", "sca.check.result",
		// syscheck (FIM) alert fields. "file" is the path in a syscheck alert;
		// syscheck.audit.* comes from whodata, which is what answers "which process
		// wrote this". All UNVERIFIED at the field-name level (docs/00-sources.md).
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
	// Every allocated file should exist, or the map is describing rules nobody wrote.
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

	runbookRE := regexp.MustCompile(`runbook_D\d+`)
	for _, r := range rules {
		name := fmt.Sprintf("rule_%d", r.ID)
		t.Run(name, func(t *testing.T) {
			if strings.TrimSpace(r.Description) == "" {
				t.Error("no description: an alert with no description is untriageable")
			}
			if r.Level < 0 || r.Level > 16 {
				t.Errorf("level %d is outside 0-16", r.Level)
			}
			// A level-0 rule raises no alert and exists only as a parent, so it needs
			// neither a runbook nor a technique; everything that alerts needs both.
			if r.Level > 0 {
				if !runbookRE.MatchString(r.Groups) {
					t.Errorf("groups %q name no runbook; every alerting rule carries runbook_Dn per docs/03-detection.md", r.Groups)
				}
				if len(r.Mitre.IDs) == 0 {
					t.Error("no MITRE technique: external firms expect a technique id on every alert")
				}
			}
			if r.Level == 0 && r.DecodedAs == "" && r.IfSID == "" {
				t.Error("a level-0 rule that matches nothing and chains from nothing is dead")
			}
			// Parents must exist, or the child silently never fires. A parent may be
			// one of ours or one of Wazuh's; anything else is a typo.
			for _, raw := range []string{r.IfSID, r.IfMatchedSI} {
				for _, id := range parseIDList(t, raw) {
					_, ours := byID[id]
					_, external := externalParents[id]
					if !ours && !external {
						t.Errorf("parent rule %d is neither one of ours nor a known Wazuh parent; the rule would never fire", id)
					}
				}
			}
			// A rule reading a Wazuh-internal alert must say so, because that is what
			// excuses it from fixture coverage.
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

// TestDescriptionInterpolationsExist catches the other half of a rename: an alert
// description referring to $(some_old_field) renders the literal text to the analyst.
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

// TestArrayFieldRulesUseUnanchoredLiterals is the test that keeps an unverified
// assumption from becoming a silent failure.
//
// How a <field> regex matches a multi-valued field — against each value, or against
// one joined string — was not verified during research (docs/00-sources.md). An
// unanchored literal matches under either behavior; an anchored one matches under at
// most one. So rules on array fields must stay unanchored, and this test enforces it
// rather than trusting a comment.
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

// matches models the subset of Wazuh matching these rules use, for one event.
//
// Deliberately narrow: presence via the \.+ idiom, otherwise the pattern as a regexp,
// with array values joined by commas. Anchors behave identically in OS_Regex and Go
// regexp for the literal patterns used here; anything more exotic would need the real
// wazuh-logtest, which the README tells an operator to run.
func matches(r rule, ev map[string]any, byID map[int]rule) (bool, error) {
	// A correlation rule fires on N matches of its parent within a timeframe, which
	// this model does not simulate. Refusing is deliberate: silently ignoring
	// if_matched_sid would make such a rule look unconditional and match every event,
	// which is the opposite of the truth and would hide a real failure behind a
	// green test.
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
			// A syscheck or SCA alert is not one of our JSON events, and pretending to
			// evaluate one against a fixture would produce a confident wrong answer.
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
			// The Wazuh idiom for "present with any value".
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

// TestEveryRuleMatchesAFixture is the central test. A rule that matches nothing in a
// fixture set generated from the real pipeline is a rule that will match nothing in
// production, and it will say so by never alerting.
func TestEveryRuleMatchesAFixture(t *testing.T) {
	rules := loadRules(t)
	fixtures := loadFixtures(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	for _, r := range rules {
		t.Run(fmt.Sprintf("rule_%d", r.ID), func(t *testing.T) {
			// A correlation rule fires on N matches of its parent, which this model
			// does not simulate; its parent is covered by its own subtest, and the
			// structural checks are in TestEveryRuleIsWellFormed.
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

// TestSummaryAndPerToolEventsAreDistinguishable pins the discriminator the rules rely
// on. If a per-tool event ever carried mcp_tool_count, or a summary carried
// mcp_baseline_state, every drift would raise two alerts and no rule could tell the
// roll-up from the finding.
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
	// The fixtures are committed to the repository and pasted into wazuh-logtest by
	// whoever verifies the rules, so they are held to the same standard as the sink
	// they came from.
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
	runbookRE := regexp.MustCompile(`runbook_(D\d+)`)
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

// TestRunbooksCoverTheRequiredSections checks the structure docs/03-detection.md
// requires, because the one thing an external analyst cannot do is improvise the parts
// that need us.
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

// TestOrdinaryDriftDoesNotPage is the false-positive control, and the reason the
// fixtures include a description change that is merely different rather than hostile.
//
// The common real cause of drift is a package upgrade shipping better descriptions. If
// that pages an analyst, the rule gets an exception carved out and then it protects
// nothing. So: an ordinary drift must raise the level-12 D4 alert and must not satisfy
// any D5 rule or the level-13 combination rule.
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

		// Drift is still drift: the D4 alert must fire.
		ok, err := matches(byID[100234], ev, byID)
		if err != nil {
			t.Fatalf("fixture %d: %v", i+1, err)
		}
		if !ok {
			t.Errorf("fixture %d is a drift event but rule 100234 does not match it", i+1)
		}

		// Nothing that reads a D5 finding may fire, including the level-13 rule that
		// combines drift with concealed instructions. Correlation rules are excluded
		// because they fire on repeated matches of a parent, and that parent is
		// checked here in its own right.
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

// TestPendingRulesMatchNothingYet is the other half of the pending-emitter marker. A rule
// marked pending that in fact matches a real event is worse than an unmarked one: the
// marker tells a reader the detector is inert, so a working detector would be ignored and
// its alerts dismissed as impossible.
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

// isSynthetic reports whether a fixture line was hand-written rather than generated. The
// synthetic lines exist to exercise M2-shaped events, so a pending rule is expected to
// match them — that is what they are for — and only the generated lines answer the
// question "does an emitter exist today".
func isSynthetic(ev map[string]any) bool {
	id, _ := ev["event_id"].(string)
	return strings.HasPrefix(id, "01JSYNTH") || ev["kind"] == "sink_gap"
}

// TestRulesStayQuietWhereTheyShould pins the negative expectations that matter, one per
// detector whose quiet case is easy to get wrong. Each entry is a real fixture shape and
// a rule that must not fire on it.
//
// Without this, a rule that matched everything would pass every other test in this file:
// "matches at least one fixture" is satisfied by matching all of them.
func TestRulesStayQuietWhereTheyShould(t *testing.T) {
	rules := loadRules(t)
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	cases := []struct {
		name string
		rule int
		// pick selects the fixture this rule must not match.
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

// TestDeployArtifactsAreWellFormed parses every XML and JSON file under deploy/.
//
// This exists because the failure it catches has already happened twice in this
// repository, both times in a comment rather than in the configuration itself: a `--`
// inside an XML comment is invalid XML, and Wazuh refuses a file it cannot parse — which
// can take down the whole ossec.conf include, not just the rule that carried the typo.
// Go's XML parser rejects the same sequence, so a test is enough and no Wazuh install is
// needed.
//
// The SCA policy is YAML and is not checked here: validating it would mean adding a
// dependency to a repository that deliberately has none, and `wazuh-logtest` and the SCA
// engine both read it on deployment.
func TestDeployArtifactsAreWellFormed(t *testing.T) {
	// ".." is the deploy directory: this package sits in deploy/wazuh.
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
			// Token-scan rather than Unmarshal: it reaches comments and every other
			// construct, where Unmarshal into a narrow struct can skip past them.
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
