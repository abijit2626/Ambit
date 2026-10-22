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
	correlationManifest = "fixtures/g-correlation.tsv"
	twoKeysAlerts       = "fixtures/g-two-keys.alerts"
	floodAlerts         = "fixtures/g-flood.alerts"
)

// Rules that still combine same_field with ignore. Each is here because it could not be shown
// safe to change, and each needs a decision of its own; the list may only shrink.
var ignoreStillPresent = map[int]string{
	100271: "parent 19007 is Wazuh's own SCA rule; an SCA event cannot be replayed offline, so the effect was not measured",
	100281: "its parent 100280 is level 0 and level-0 matches are not counted, so the rule never fires; ignore is moot until that is redesigned",
	100282: "same as 100281",
}

// Rules the recorded run shows never firing at all, for the reason above.
var knownSilent = map[int]bool{100281: true, 100282: true}

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
		if knownSilent[row.rule] {
			if alerted+suppressed != 0 {
				t.Errorf("rule %d now matches in the recorded run (%d alerted, %d suppressed); take it out of knownSilent and expect one alert per key", row.rule, alerted, suppressed)
			}
			continue
		}
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
		if knownSilent[row.rule] {
			continue
		}
		block := lines[row.floodFirst-1 : row.floodLast]
		alerted, suppressed := countAlerts(block, row.rule)
		if suppressed != 0 || alerted != 4 {
			t.Errorf("rule %d: %d alerted and %d suppressed over %d events from one key, want 4 and 0 (one per %d)", row.rule, alerted, suppressed, len(block), row.threshold)
		}
	}
}
