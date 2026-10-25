package wazuh

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// `ignore` on a Wazuh rule silences that rule for every value of same_field, not per value, so one
// session's (or server's, or endpoint's) alert hides every other key's alert for the whole window.
// The recorded runs under fixtures/g-*.alerts show it on the 4.14.8 image; see
// scripts/gen-correlation-fixtures.sh and scripts/record-correlation-alerts.sh.

const (
	d10Manifest         = "fixtures/g-d10.tsv"
	d10Alerts           = "fixtures/g-d10.alerts"
	correlationManifest = "fixtures/g-correlation.tsv"
	twoKeysAlerts       = "fixtures/g-two-keys.alerts"
	floodAlerts         = "fixtures/g-flood.alerts"
)

// Rules that still combine same_field with ignore. Each is here because it could not be shown
// safe to change, and each needs a decision of its own; the list may only shrink.
var ignoreStillPresent = map[int]string{}

func TestNoCorrelationRuleSilencesOtherKeysWithIgnore(t *testing.T) {
	seen := map[int]bool{}
	for _, r := range loadRules(t) {
		if r.Ignore == 0 || r.SameField == "" {
			continue
		}
		seen[r.ID] = true
		if _, ok := ignoreStillPresent[r.ID]; !ok {
			t.Errorf("rule %d (%s) has ignore=%d together with same_field %q: ignore is per rule, not per %s value, so one key's alert silences every other key's for %ds; drop ignore",
				r.ID, r.file, r.Ignore, r.SameField, r.SameField, r.Ignore)
		}
	}
	for id, why := range ignoreStillPresent {
		if !seen[id] {
			t.Errorf("rule %d no longer has ignore with same_field; remove it from ignoreStillPresent (%s)", id, why)
		}
	}
}

type correlationRow struct {
	rule                  int
	field                 string
	threshold             int
	twoFirst, twoLast     int
	floodFirst, floodLast int
	source                string
}

func readManifest(t *testing.T) []correlationRow {
	t.Helper()
	raw, err := os.ReadFile(correlationManifest)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with scripts/gen-correlation-fixtures.sh)", correlationManifest, err)
	}
	var rows []correlationRow
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if i == 0 {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 8 {
			t.Fatalf("%s line %d: want 8 columns, got %d", correlationManifest, i+1, len(c))
		}
		n := func(s string) int {
			v, err := strconv.Atoi(s)
			if err != nil {
				t.Fatalf("%s line %d: %q is not a number", correlationManifest, i+1, s)
			}
			return v
		}
		rows = append(rows, correlationRow{n(c[0]), c[1], n(c[2]), n(c[3]), n(c[4]), n(c[5]), n(c[6]), c[7]})
	}
	return rows
}

type alertLine struct {
	rule  int
	alert bool
}

func readAlerts(t *testing.T, path string) []alertLine {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (record with scripts/record-correlation-alerts.sh)", path, err)
	}
	var out []alertLine
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 4 || !strings.HasPrefix(f[3], "alert=") {
			t.Fatalf("%s: unreadable line %q", path, line)
		}
		id, _ := strconv.Atoi(f[1]) // "none" -> 0
		out = append(out, alertLine{rule: id, alert: f[3] == "alert=yes"})
	}
	return out
}

func countAlerts(lines []alertLine, rule int) (alerted, suppressed int) {
	for _, l := range lines {
		if l.rule != rule {
			continue
		}
		if l.alert {
			alerted++
		} else {
			suppressed++
		}
	}
	return
}

// Two keys, each sent exactly the rule's threshold of matching events: both must alert. With ignore
// the second key's match is recorded as the rule id with alert=no.
func TestEachKeyRaisesItsOwnCorrelationAlert(t *testing.T) {
	lines := readAlerts(t, twoKeysAlerts)
	for _, row := range readManifest(t) {
		block := lines[row.twoFirst-1 : row.twoLast]
		if got, want := row.twoLast-row.twoFirst+1, 2*row.threshold; got != want {
			t.Fatalf("rule %d: manifest block holds %d events, want two keys of %d", row.rule, got, row.threshold)
		}
		alerted, suppressed := countAlerts(block, row.rule)
		if suppressed != 0 || alerted != 2 {
			t.Errorf("rule %d: %d alerted and %d suppressed for two keys, want 2 and 0 (suppression is ignore hiding the second key)", row.rule, alerted, suppressed)
		}
	}
}

// One key sent four times the threshold: without ignore the rule re-fires once per threshold, not on
// every event, so removing ignore does not turn a flood into an alert per event.
func TestOneKeyFloodAlertsOncePerThreshold(t *testing.T) {
	lines := readAlerts(t, floodAlerts)
	for _, row := range readManifest(t) {
		block := lines[row.floodFirst-1 : row.floodLast]
		alerted, suppressed := countAlerts(block, row.rule)
		if suppressed != 0 || alerted != 4 {
			t.Errorf("rule %d: %d alerted and %d suppressed over %d events from one key, want 4 and 0 (one per %d)", row.rule, alerted, suppressed, len(block), row.threshold)
		}
	}
}

// D10 (100281, 100282) is not one key sent N times, so it has its own scenarios: g-d10.tsv names each
// scenario's lines in g-d10.jsonl and g-d10.alerts records the replay, one wazuh-logtest process per
// scenario. 100280 (level 1, below the default log alert level) is counted but never alerts.
type d10Want struct {
	r281, r282 int // alerts raised by 100281 and 100282
	r302       int // tool_posts that alert as 100302, a secret in a network command
	r280       int // fp_sighting events that matched only 100280, so were counted and not alerted
	none       int // events no rule matched: tool_posts, whose fingerprint D10 does not count
}

var d10Expected = map[string]d10Want{
	// one session repeating a fingerprint is ordinary behavior, not propagation
	"one-session-x12": {r280: 12},
	// a different session each time: 100281 from the 2nd sighting, 100282 on the 5th and 9th
	"twelve-sessions": {r281: 9, r282: 2, r280: 1},
	// without emit-once in ambitd, session B repeating a fingerprint A saw keeps alerting
	"a-once-then-b-x20": {r281: 15, r282: 5, r280: 1},
	"a-x20-then-b-once": {r281: 1, r280: 20},
	// with emit-once the same two scenarios reach Wazuh as A, B
	"emit-once-a-then-b": {r281: 1, r280: 1},
	// ignore would have let one fingerprint's alert hide the other's
	"two-fingerprints": {r281: 2, r280: 2},
	// different sessions seeing different fingerprints is not propagation: same_field keeps them apart
	"unrelated-fingerprints": {r280: 3},
	// the reason fp_sighting exists: tool_posts that alert as 100302 keep that alert, and their sightings are
	// counted as if there were no collision (compare twelve-sessions)
	"collision-100302-alternate": {r281: 9, r282: 2, r302: 6, r280: 1, none: 6},
	// an ambitd older than fp_sighting puts the fingerprint only on the tool_post, which D10 no longer counts
	"tool-post-only": {none: 12},
}

type d10Scenario struct {
	name        string
	first, last int
}

func readD10Manifest(t *testing.T) []d10Scenario {
	t.Helper()
	raw, err := os.ReadFile(d10Manifest)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with scripts/gen-correlation-fixtures.sh)", d10Manifest, err)
	}
	var out []d10Scenario
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if i == 0 {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 4 {
			t.Fatalf("%s line %d: want 4 columns, got %d", d10Manifest, i+1, len(c))
		}
		first, err1 := strconv.Atoi(c[1])
		last, err2 := strconv.Atoi(c[2])
		if err1 != nil || err2 != nil {
			t.Fatalf("%s line %d: first and last must be numbers", d10Manifest, i+1)
		}
		out = append(out, d10Scenario{c[0], first, last})
	}
	return out
}

func TestD10ScenariosAlertAsDesigned(t *testing.T) {
	lines := readAlerts(t, d10Alerts)
	scenarios := readD10Manifest(t)
	seen := map[string]bool{}
	for _, sc := range scenarios {
		seen[sc.name] = true
		want, ok := d10Expected[sc.name]
		if !ok {
			t.Errorf("scenario %q in %s has no expectation in d10Expected", sc.name, d10Manifest)
			continue
		}
		if sc.last > len(lines) {
			t.Fatalf("scenario %q ends at line %d but %s records %d lines; re-record with scripts/record-correlation-alerts.sh", sc.name, sc.last, d10Alerts, len(lines))
		}
		block := lines[sc.first-1 : sc.last]
		var got d10Want
		for _, l := range block {
			switch {
			case l.rule == 100281 && l.alert:
				got.r281++
			case l.rule == 100282 && l.alert:
				got.r282++
			case l.rule == 100302 && l.alert:
				got.r302++
			case l.rule == 100280 && !l.alert:
				got.r280++
			case l.rule == 0 && !l.alert:
				got.none++
			default:
				t.Errorf("scenario %q: unexpected line rule %d alert=%v", sc.name, l.rule, l.alert)
			}
		}
		if got != want {
			t.Errorf("scenario %q: got %+v, want %+v", sc.name, got, want)
		}
	}
	for name := range d10Expected {
		if !seen[name] {
			t.Errorf("d10Expected names scenario %q that is not in %s", name, d10Manifest)
		}
	}
}

// The recorded run proves what the rules did when it was made; this proves the rules still say it.
// Each assertion is the property a scenario above depends on, so a rule edit that is not re-recorded
// fails here and one that is re-recorded fails there.
func TestD10RuleShape(t *testing.T) {
	byID := indexRules(loadRules(t))
	r280, r281, r282 := byID[100280], byID[100281], byID[100282]

	if len(r280.Fields) == 0 || r280.Fields[0].Name != "kind" || r280.Fields[0].Pattern != "^fp_sighting$" {
		t.Errorf("rule 100280 must match only fp_sighting events (first field kind = ^fp_sighting$), got %+v: a tool event can alert as another rule, and Wazuh counts only the rule that won", r280.Fields)
	}
	if r280.Level < 1 {
		t.Errorf("rule 100280 is level %d; a level 0 match is not counted by if_matched_sid, so 100281 and 100282 can never fire", r280.Level)
	}
	if r280.Level >= 3 {
		t.Errorf("rule 100280 is level %d; it must stay below the default log alert level of 3 or every notable fingerprint becomes an alert", r280.Level)
	}
	if got := strings.TrimSpace(r281.IfMatchedSI); got != "100280" {
		t.Errorf("rule 100281 if_matched_sid = %q, want 100280", got)
	}
	if r281.SameField != "prov_fp_notable" || r281.NotSameFld != "session_id" {
		t.Errorf("rule 100281 same_field=%q not_same_field=%q, want prov_fp_notable and session_id: the same fingerprint in a different session", r281.SameField, r281.NotSameFld)
	}
	if got := strings.TrimSpace(r282.IfMatchedSI); got != "100281" {
		t.Errorf("rule 100282 if_matched_sid = %q, want 100281: once 100281 alerts on an event it is no longer a 100280 match, so counting 100280 never reaches 5", got)
	}
	if r282.SameField != "prov_fp_notable" {
		t.Errorf("rule 100282 same_field = %q, want prov_fp_notable", r282.SameField)
	}
	if r282.Level <= r281.Level {
		t.Errorf("rule 100282 (level %d) must outrank 100281 (level %d)", r282.Level, r281.Level)
	}
	for _, r := range []rule{r281, r282} {
		if r.Ignore != 0 {
			t.Errorf("rule %d has ignore=%d; it silences every fingerprint, not one", r.ID, r.Ignore)
		}
	}
}

// The point of fp_sighting is that no other rule competes for it. Any rule that also matches one would win
// it whenever its level is higher, and D10 would silently stop counting those sightings, which is the
// 100302 collision again. This checks every fp_sighting in the fixtures against every rule the model covers.
func TestNothingButRule100280MatchesAnFPSighting(t *testing.T) {
	rules := loadRules(t)
	byID := indexRules(rules)
	var sightings int
	for _, fixture := range []string{fixturesPath, "fixtures/g-d10.jsonl"} {
		for i, ev := range loadFixtureFile(t, fixture) {
			if ev["kind"] != "fp_sighting" {
				continue
			}
			sightings++
			for _, r := range rules {
				if !modelled(r) {
					continue
				}
				ok, err := matches(r, ev, byID)
				if err != nil {
					t.Fatalf("%s line %d, rule %d: %v", fixture, i+1, r.ID, err)
				}
				if ok && r.ID != 100280 {
					t.Errorf("%s line %d: rule %d matches an fp_sighting; it would win the event and D10 would not count it", fixture, i+1, r.ID)
				}
			}
		}
	}
	if sightings == 0 {
		t.Fatal("no fp_sighting events in the fixtures; the check above checked nothing")
	}
}

// The other events ambitd derives are built the same way: identity, session and their own fields, nothing a
// tool rule keys on. Each must be matched only by the rules written for it, or a louder rule would win it
// and its own alert would never be raised.
func TestDerivedEventsAreMatchedOnlyByTheirOwnRules(t *testing.T) {
	own := map[string]map[int]bool{
		"session_mode":      {100200: true},
		"session_no_prompt": {100206: true, 100207: true},
		"sandbox_denial":    {100304: true, 100305: true},
	}
	rules := loadRules(t)
	byID := indexRules(rules)
	seen := map[string]int{}
	for _, fixture := range []string{fixturesPath, alonePath} {
		for i, ev := range loadFixtureFile(t, fixture) {
			kind, _ := ev["kind"].(string)
			allowed, ok := own[kind]
			if !ok {
				continue
			}
			seen[kind]++
			for _, r := range rules {
				if !modelled(r) {
					continue
				}
				hit, err := matches(r, ev, byID)
				if err != nil {
					t.Fatalf("%s line %d, rule %d: %v", fixture, i+1, r.ID, err)
				}
				if hit && !allowed[r.ID] {
					t.Errorf("%s line %d: rule %d matches a %s; only %v should", fixture, i+1, r.ID, kind, allowed)
				}
			}
		}
	}
	for kind := range own {
		if seen[kind] == 0 {
			t.Errorf("no %s event in the fixtures; the check above checked nothing for it", kind)
		}
	}
}
