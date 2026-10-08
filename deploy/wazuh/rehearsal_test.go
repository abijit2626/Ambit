package wazuh

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	rehearsalEnv = "AMBIT_REHEARSAL_DIR"

	rehearsalOnlyEnv = "AMBIT_REHEARSAL_ONLY"

	maxSamplesPerRunbook = 2
)

var (
	runbookGroupRe = regexp.MustCompile(`^runbook_([A-Za-z]+[0-9]+)$`)
	interpolateRe  = regexp.MustCompile(`\$\(([A-Za-z0-9_]+)\)`)
	backtickedRe   = regexp.MustCompile("`([a-z][a-z0-9_]*)`")
)

func groupTokens(r rule) []string {
	var out []string
	for _, g := range strings.Split(r.Groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func runbookOf(r rule) string {
	for _, g := range groupTokens(r) {
		if m := runbookGroupRe.FindStringSubmatch(g); m != nil {
			return m[1]
		}
	}
	return ""
}

type sample struct {
	line      int
	synthetic bool
	top       rule
	fired     []rule
	event     map[string]any
	raw       string
}

type plan struct {
	id       string
	runbook  string
	rules    []rule
	samples  []sample
	skipWhy  string
	skipNote string
}

func runbookIDs(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(runbooksDir, "*.md"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	out := map[string]string{}
	for _, p := range paths {
		base := filepath.Base(p)
		id := strings.SplitN(base, "-", 2)[0]
		out[id] = base
	}
	return out
}

func naturalLess(a, b string) bool {
	split := func(s string) (string, int) {
		i := 0
		for i < len(s) && (s[i] < '0' || s[i] > '9') {
			i++
		}
		n, _ := strconv.Atoi(s[i:])
		return s[:i], n
	}
	pa, na := split(a)
	pb, nb := split(b)
	if pa != pb {
		return pa < pb
	}
	return na < nb
}

func planRehearsals(t *testing.T, only map[string]bool) []plan {
	t.Helper()
	rules := loadRules(t)
	fixtures := loadFixtures(t)
	rawBytes, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	rawLines := strings.Split(strings.TrimSpace(string(rawBytes)), "\n")
	if len(rawLines) != len(fixtures) {
		t.Fatalf("fixture line count %d != parsed %d", len(rawLines), len(fixtures))
	}
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	books := runbookIDs(t)
	var ids []string
	for id := range books {
		if len(only) == 0 || only[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return naturalLess(ids[i], ids[j]) })

	var out []plan
	for _, id := range ids {
		p := plan{id: id, runbook: books[id]}
		var matchable []rule
		var wazuhSourced, correlation int
		for _, r := range rules {
			if runbookOf(r) != id {
				continue
			}
			p.rules = append(p.rules, r)
			switch {
			case r.isCorrelation():
				correlation++
			case r.hasGroup(groupWazuhSourced) || readsExternalEvent(r, byID, t):
				wazuhSourced++
			case r.Level < 1:

			default:
				matchable = append(matchable, r)
			}
		}

		for i, ev := range fixtures {
			var fired []rule
			for _, r := range matchable {
				ok, err := matches(r, ev, byID)
				if err == nil && ok {
					fired = append(fired, r)
				}
			}
			if len(fired) == 0 {
				continue
			}
			sort.Slice(fired, func(a, b int) bool {
				if fired[a].Level != fired[b].Level {
					return fired[a].Level > fired[b].Level
				}
				return fired[a].ID < fired[b].ID
			})
			p.samples = append(p.samples, sample{
				line: i + 1, synthetic: isSynthetic(ev), top: fired[0], fired: fired,
				event: ev, raw: rawLines[i],
			})
		}

		sort.SliceStable(p.samples, func(a, b int) bool {
			sa, sb := p.samples[a], p.samples[b]
			if sa.synthetic != sb.synthetic {
				return !sa.synthetic
			}
			if sa.top.Level != sb.top.Level {
				return sa.top.Level > sb.top.Level
			}
			return sa.line < sb.line
		})
		var picked []sample
		seen := map[int]bool{}
		for _, s := range p.samples {
			if seen[s.top.ID] {
				continue
			}
			seen[s.top.ID] = true
			picked = append(picked, s)
			if len(picked) == maxSamplesPerRunbook {
				break
			}
		}
		p.samples = picked

		if len(p.samples) == 0 {
			p.skipWhy, p.skipNote = skipReason(len(p.rules), len(matchable), wazuhSourced, correlation)
		}
		out = append(out, p)
	}
	return out
}

func skipReason(total, matchable, wazuhSourced, correlation int) (why, note string) {
	switch {
	case total == 0:
		return "no rule points at this runbook",
			"Nothing raises this alert yet. Rehearse it only once a rule exists."
	case matchable == 0 && wazuhSourced > 0 && correlation == 0:
		return "its rules read Wazuh-internal alerts (syscheck FIM or SCA results)",
			"The offline fixtures cannot contain one. On a test endpoint, cause the condition " +
				"(edit a watched file, break a managed-settings key), copy the alert the manager " +
				"produces, and give the analyst that."
	case matchable == 0 && correlation > 0 && wazuhSourced == 0:
		return "its rules fire on repeated matches inside a time window",
			"The offline model does not simulate correlation. Drive the real condition on a test " +
				"endpoint and use the alert the manager produces."
	case matchable == 0:
		return "its rules are correlation rules or read Wazuh-internal alerts",
			"Neither can be built offline. Produce the alert on a test endpoint and use that."
	default:
		return "no fixture event satisfies its rules",
			"The rules exist but nothing in the generated fixtures triggers them. Either add a " +
				"fixture, or the rule is waiting on an emitter that does not exist yet."
	}
}

func interpolate(desc string, ev map[string]any) string {
	return interpolateRe.ReplaceAllStringFunc(strings.TrimSpace(desc), func(m string) string {
		name := interpolateRe.FindStringSubmatch(m)[1]
		raw, ok := ev[name]
		if !ok {
			return m
		}
		return renderValue(raw)
	})
}

func alertJSON(s sample) ([]byte, error) {
	var groups []string
	groups = append(groups, groupTokens(s.top)...)
	alert := map[string]any{
		"rule": map[string]any{
			"id":          strconv.Itoa(s.top.ID),
			"level":       s.top.Level,
			"description": interpolate(s.top.Description, s.event),
			"groups":      groups,
			"mitre":       map[string]any{"id": s.top.Mitre.IDs},
		},
		"decoder":  map[string]any{"name": "json"},
		"location": "events.jsonl",
		"data":     s.event,
		"full_log": s.raw,
	}
	return json.MarshalIndent(alert, "", "  ")
}

func section(md, heading string) string {
	lines := strings.Split(md, "\n")
	var body []string
	in := false
	for _, l := range lines {
		if strings.HasPrefix(l, "## ") {
			if in {
				break
			}
			in = strings.Contains(l, heading)
			continue
		}
		if in {
			body = append(body, l)
		}
	}
	return strings.TrimSpace(strings.Join(body, "\n"))
}

func assertedFields(runbook string, ev map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range backtickedRe.FindAllStringSubmatch(section(runbook, "What this alert asserts"), -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if raw, ok := ev[name]; ok {
			out = append(out, fmt.Sprintf("  - `%s` = `%s`", name, renderValue(raw)))
		}
	}
	return out
}

const analystReadme = `# Runbook rehearsal

You have been given one or more alerts and the runbook for each. You are the test.

The runbooks say they are written for an analyst with no access to our source tree or our
systems. This exercise checks whether that is true. You are not being graded; the runbook is.

**How to run it**

1. Open one directory (for example ` + "`D4/`" + `). It holds a sample alert and the runbook for it.
2. Work the alert using only those two files and whatever you would normally have. Do not
   ask the team what a field means. If you want to, write the question down in
   ` + "`FEEDBACK.md`" + ` instead: a question you had to ask is a finding.
3. Decide: is this alert actionable, what would you do next, and does anything require the
   team (the runbook says what does)?
4. Fill in one ` + "`FEEDBACK.md`" + ` section per alert before you talk to anyone.

**What these are.** The alerts are built from test data, not from a real incident, and they
are assembled offline in Wazuh's alert shape. Treat the endpoint, user and session names as
made up.
`

const feedbackTemplate = `# Feedback

One section per alert. Be specific; "step 3 was unclear" is useful, "good" is not.

## Alert: <runbook id and rule id>

- **Time from opening the alert to your first decision (minutes):**
- **Your decision** (page / escalate to the team / close as benign / could not tell):
- **What you concluded the alert asserts, in your own words:**
- **What you concluded it does NOT assert:**
- **Steps you could not do with only the alert and the runbook** (step number, what was missing):
- **Terms or fields you had to guess at:**
- **Questions you would have asked the team:**
- **Anything in the runbook that was wrong, or that you did not trust:**
`

const answerKeyIntro = `# Answer key. Do not give this directory to the analyst.

How to score a rehearsal: the criterion is not whether the analyst got the "right" verdict.
It is whether they reached a verdict, and an escalation decision, using only the alert and
the runbook, without asking us what something meant. Record each question they asked, each
step they could not do, and each term they guessed at. Every one is a defect in the runbook.

The rule shown for each sample is the one our offline model picks (the highest-level rule
the event satisfies). Wazuh decides which rule actually reports an event, so confirm with
wazuh-logtest before relying on the rule id.
`

func writePackets(t *testing.T, dir string, plans []plan) (built int) {
	t.Helper()
	analyst := filepath.Join(dir, "analyst")
	key := filepath.Join(dir, "answer-key")
	for _, d := range []string{analyst, key} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(analyst, "README.md"), []byte(analystReadme))
	write(filepath.Join(analyst, "FEEDBACK.md"), []byte(feedbackTemplate))

	manifest := []string{answerKeyIntro, "## Packets\n"}
	var skipped []string
	for _, p := range plans {
		if len(p.samples) == 0 {
			skipped = append(skipped, fmt.Sprintf("- **%s**: no packet. %s. %s", p.id, capitalize(p.skipWhy), p.skipNote))
			continue
		}
		built++
		rb, err := os.ReadFile(filepath.Join(runbooksDir, p.runbook))
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(analyst, p.id, "runbook.md"), rb)

		k := []string{fmt.Sprintf("# Answer key: %s\n\nRunbook: `runbooks/%s`\n", p.id, p.runbook)}
		for i, s := range p.samples {
			alert, err := alertJSON(s)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(analyst, p.id, fmt.Sprintf("alert-%d.json", i+1)), append(alert, '\n'))

			origin := "generated by running ambitd and mcp-interpose"
			if s.synthetic {
				origin = "SYNTHETIC: hand-built to exercise this shape, not produced by the pipeline"
			}
			var fired []string
			for _, r := range s.fired {
				fired = append(fired, fmt.Sprintf("%d (level %d)", r.ID, r.Level))
			}
			k = append(k, fmt.Sprintf("## Sample %d (`alert-%d.json`)\n", i+1, i+1),
				fmt.Sprintf("- Fixture line %d of `fixtures/events.sample.jsonl`; %s.", s.line, origin),
				fmt.Sprintf("- Alert rule: **%d**, level %d: %s", s.top.ID, s.top.Level, interpolate(s.top.Description, s.event)),
				fmt.Sprintf("- Every runbook rule this event satisfies: %s.", strings.Join(fired, ", ")))
			if fields := assertedFields(string(rb), s.event); len(fields) > 0 {
				k = append(k, "- Fields the runbook's \"What this alert asserts\" names, as they appear in this event:")
				k = append(k, fields...)
			}
			k = append(k, "")
		}
		for _, h := range []string{"What requires us", "Escalation"} {
			if body := section(string(rb), h); body != "" {
				k = append(k, fmt.Sprintf("## The runbook's own \"%s\" section\n\nThe analyst's escalation decision should agree with this.\n\n%s\n", h, body))
			}
		}
		write(filepath.Join(key, p.id+".md"), []byte(strings.Join(k, "\n")))
		manifest = append(manifest, fmt.Sprintf("- **%s**: %d sample(s), top rule(s) %s", p.id, len(p.samples), topRules(p.samples)))
	}
	if len(skipped) > 0 {
		manifest = append(manifest, "\n## No packet\n\nThese runbooks cannot be rehearsed from the offline fixtures. Rehearsing them is still part of the M1 criterion.\n")
		manifest = append(manifest, skipped...)
	}
	write(filepath.Join(key, "00-manifest.md"), []byte(strings.Join(manifest, "\n")+"\n"))
	return built
}

func topRules(ss []sample) string {
	var ids []string
	for _, s := range ss {
		ids = append(ids, strconv.Itoa(s.top.ID))
	}
	return strings.Join(ids, ", ")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func onlyFromEnv() map[string]bool {
	raw := strings.TrimSpace(os.Getenv(rehearsalOnlyEnv))
	if raw == "" {
		return nil
	}
	out := map[string]bool{}
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = true
		}
	}
	return out
}

func TestWriteRehearsalPackets(t *testing.T) {
	dir := os.Getenv(rehearsalEnv)
	if dir == "" {
		t.Skipf("set %s to write rehearsal packets (scripts/runbook-rehearsal.sh does)", rehearsalEnv)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("%s must be absolute: go test runs in the package directory, so a relative path would land in the wrong place", rehearsalEnv)
	}
	only := onlyFromEnv()
	plans := planRehearsals(t, only)
	if len(plans) == 0 {
		t.Fatalf("%s=%q matched no runbook", rehearsalOnlyEnv, os.Getenv(rehearsalOnlyEnv))
	}
	built := writePackets(t, dir, plans)
	t.Logf("wrote %d packet(s), %d without one, to %s", built, len(plans)-built, dir)
}

func TestRehearsalPacketsAreSound(t *testing.T) {
	plans := planRehearsals(t, nil)
	dir := t.TempDir()
	built := writePackets(t, dir, plans)

	byID := map[int]rule{}
	for _, r := range loadRules(t) {
		byID[r.ID] = r
	}

	for _, p := range plans {
		_, err := os.Stat(filepath.Join(dir, "analyst", p.id, "alert-1.json"))
		switch {
		case len(p.samples) > 0 && err != nil:
			t.Errorf("%s has samples but no alert-1.json: %v", p.id, err)
		case len(p.samples) == 0 && (p.skipWhy == "" || p.skipNote == ""):
			t.Errorf("%s has no packet and no reason", p.id)
		case len(p.samples) == 0 && err == nil:
			t.Errorf("%s has no samples but an alert file exists", p.id)
		}
	}

	want := map[string]bool{"D4": true, "D5": true, "D2": true, "R2": true}
	for _, p := range plans {
		if want[p.id] && len(p.samples) == 0 {
			t.Errorf("%s should have a packet from the generated fixtures but has none (%s)", p.id, p.skipWhy)
		}
	}

	for _, p := range plans {
		if p.id == "D12" && len(p.samples) != 0 {
			t.Errorf("%s reads Wazuh-internal alerts, so a fixture-built alert would be invented", p.id)
		}
	}
	if built == 0 {
		t.Fatal("no packets were built at all")
	}

	alerts, _ := filepath.Glob(filepath.Join(dir, "analyst", "*", "alert-*.json"))
	if len(alerts) == 0 {
		t.Fatal("no alert files written")
	}
	for _, a := range alerts {
		raw, err := os.ReadFile(a)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Rule struct {
				ID          string `json:"id"`
				Level       int    `json:"level"`
				Description string `json:"description"`
			} `json:"rule"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s is not valid JSON: %v", a, err)
		}
		id, _ := strconv.Atoi(got.Rule.ID)
		r, ok := byID[id]
		if !ok {
			t.Errorf("%s names rule %s, which does not exist", a, got.Rule.ID)
			continue
		}
		if got.Rule.Level != r.Level {
			t.Errorf("%s says level %d; rule %d is level %d", a, got.Rule.Level, id, r.Level)
		}
		if strings.Contains(got.Rule.Description, "$(") {
			t.Errorf("%s has an uninterpolated description: %q", a, got.Rule.Description)
		}
		if _, ok := got.Data["endpoint_id"]; !ok {
			t.Errorf("%s carries no event data", a)
		}
	}

	err := filepath.Walk(filepath.Join(dir, "analyst"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, leak := range []string{"Answer key", "answer-key", "SYNTHETIC", "Fixture line"} {
			if strings.Contains(string(raw), leak) {
				t.Errorf("%s contains %q, which belongs only in the answer key", path, leak)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "answer-key", "00-manifest.md")); err != nil {
		t.Errorf("no manifest: %v", err)
	}
}

func TestRunbookGroupMatchingIsExact(t *testing.T) {

	r := rule{Groups: "ambit_d10,runbook_D10,"}
	if got := runbookOf(r); got != "D10" {
		t.Errorf("runbookOf = %q, want D10", got)
	}
	if !r.hasGroup("runbook_D1") {
		t.Fatal("test premise changed: hasGroup is no longer a substring match")
	}
	if runbookOf(rule{Groups: "runbook_D1,"}) != "D1" {
		t.Error("D1 not recognised")
	}
}
