package wazuh

// The SCA policies and the M0 managed-settings bundle must agree.
//
// The full policy asserts enforcement keys (bypass mode, sandbox, egress allowlist) that
// the observation-only M0 bundle deliberately omits, so deploying both makes rule 100270
// fire on every endpoint from the first scan. The M0 policies are the subsets that the M0
// bundle satisfies. These tests keep that true: a subset check cannot drift from the full
// policy, a check the bundle fails cannot creep into the M0 policy, and a check the bundle
// passes cannot be dropped from it without anyone noticing.
//
// SCA matches a regex against file text, line by line. The tests do the same, so a pattern
// that only works across lines fails here as it would on an agent. They do not run Wazuh:
// p: and c: rules, which inspect the live endpoint, are treated as satisfied, and an f:
// rule with no regex passes if the bundle exists. RE2 stands in for PCRE2, which the
// patterns used here do not leave the common subset of.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	scaDir     = "sca"
	m0BundleFn = "../claude-code/managed-settings.m0.json"
)

type scaCheck struct {
	id        int
	raw       string // the check's block, byte for byte
	condition string
	rules     []string
}

type scaPolicy struct {
	policyID     string
	requirements string // the applicability block, byte for byte
	checks       map[int]scaCheck
	order        []int
}

var (
	scaCheckStartRe = regexp.MustCompile(`^  - id: (\d+)$`)
	scaPolicyIDRe   = regexp.MustCompile(`(?m)^policy:\n(?:[^\n]*\n)*?  id: "([^"]+)"`)
)

// parseSCA reads the little of the policy files these tests need, without a YAML library:
// the repository has no dependencies and a security tool should not gain one for a test.
func parseSCA(t *testing.T, path string) scaPolicy {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)
	p := scaPolicy{checks: map[int]scaCheck{}}
	if m := scaPolicyIDRe.FindStringSubmatch(text); m != nil {
		p.policyID = m[1]
	}

	lines := strings.Split(text, "\n")
	checksAt, reqAt := -1, -1
	for i, l := range lines {
		switch l {
		case "requirements:":
			reqAt = i
		case "checks:":
			checksAt = i
		}
	}
	if checksAt < 0 || reqAt < 0 || reqAt > checksAt {
		t.Fatalf("%s: could not find requirements: and checks: in order", path)
	}
	p.requirements = strings.TrimRight(strings.Join(lines[reqAt:checksAt], "\n"), "\n")

	var cur *scaCheck
	var block []string
	flush := func() {
		if cur == nil {
			return
		}
		cur.raw = strings.TrimRight(strings.Join(block, "\n"), "\n")
		p.checks[cur.id] = *cur
		p.order = append(p.order, cur.id)
	}
	inRules := false
	for _, l := range lines[checksAt+1:] {
		if m := scaCheckStartRe.FindStringSubmatch(l); m != nil {
			flush()
			id, _ := strconv.Atoi(m[1])
			cur = &scaCheck{id: id}
			block = nil
			inRules = false
		}
		if cur == nil {
			continue
		}
		block = append(block, l)
		trimmed := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(trimmed, "condition:"):
			cur.condition = strings.TrimSpace(strings.TrimPrefix(trimmed, "condition:"))
		case trimmed == "rules:":
			inRules = true
		case inRules && strings.HasPrefix(trimmed, "- '"):
			cur.rules = append(cur.rules, strings.TrimSuffix(strings.TrimPrefix(trimmed, "- '"), "'"))
		case inRules && trimmed != "" && !strings.HasPrefix(trimmed, "- "):
			inRules = false
		}
	}
	flush()
	if len(p.checks) == 0 {
		t.Fatalf("%s: no checks found", path)
	}
	return p
}

// evalBundleRule reports whether one rule is satisfied by the M0 bundle text. ok is false
// for a rule kind these tests cannot evaluate offline (processes, commands, directories).
func evalBundleRule(t *testing.T, rule string, bundle []string) (pass, ok bool) {
	t.Helper()
	switch {
	case strings.HasPrefix(rule, "p:"), strings.HasPrefix(rule, "c:"), strings.HasPrefix(rule, "d:"):
		return true, false
	case strings.HasPrefix(rule, "f:"):
		_, pattern, hasRegex := strings.Cut(rule, " -> r:")
		if !hasRegex {
			// Existence only. The bundle exists, since it was just read.
			return true, true
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("pattern %q does not compile: %v", pattern, err)
		}
		for _, line := range bundle {
			if re.MatchString(line) {
				return true, true
			}
		}
		return false, true
	}
	t.Fatalf("rule %q has a kind these tests do not know", rule)
	return false, false
}

// satisfied reports whether the bundle satisfies a check.
func (c scaCheck) satisfied(t *testing.T, bundle []string) bool {
	t.Helper()
	var passed, total int
	for _, r := range c.rules {
		pass, ok := evalBundleRule(t, r, bundle)
		if !ok {
			// A live-endpoint rule: assume it holds, so the verdict rests on the
			// file-text rules alone.
			continue
		}
		total++
		if pass {
			passed++
		}
	}
	if total == 0 {
		return true
	}
	if c.condition == "all" {
		return passed == total
	}
	return passed > 0
}

func failingChecks(t *testing.T, p scaPolicy, bundle []string) []int {
	t.Helper()
	var out []int
	for _, id := range p.order {
		if !p.checks[id].satisfied(t, bundle) {
			out = append(out, id)
		}
	}
	sort.Ints(out)
	return out
}

func loadBundle(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(m0BundleFn)
	if err != nil {
		t.Fatalf("read M0 bundle: %v", err)
	}
	return strings.Split(string(raw), "\n")
}

// scaPairs are the full policy and its M0 subset, per platform.
var scaPairs = []struct{ name, full, m0 string }{
	{"unix", "ambit_managed_settings.yml", "ambit_managed_settings_m0.yml"},
	{"windows", "ambit_managed_settings_windows.yml", "ambit_managed_settings_windows_m0.yml"},
}

func TestM0PoliciesAreVerbatimSubsetsOfTheFullPolicies(t *testing.T) {
	for _, pair := range scaPairs {
		t.Run(pair.name, func(t *testing.T) {
			full := parseSCA(t, filepath.Join(scaDir, pair.full))
			m0 := parseSCA(t, filepath.Join(scaDir, pair.m0))
			if m0.policyID != full.policyID {
				t.Errorf("policy id %q differs from the full policy's %q: the manager rules match one id, so a different one runs and never alerts", m0.policyID, full.policyID)
			}
			if m0.requirements != full.requirements {
				t.Error("the applicability block differs from the full policy's; it is what keeps a deleted bundle from making the policy not applicable")
			}
			for _, id := range m0.order {
				want, ok := full.checks[id]
				if !ok {
					t.Errorf("check %d is not in the full policy", id)
					continue
				}
				if m0.checks[id].raw != want.raw {
					t.Errorf("check %d differs from the full policy's. Regenerate it from there rather than editing it here", id)
				}
			}
		})
	}
}

func TestFullPoliciesFailTheM0BundleOnlyWhereEnforcementIsAsserted(t *testing.T) {
	bundle := loadBundle(t)
	want := map[string][]int{
		"unix":    {10002, 10003, 10004},
		"windows": {10002},
	}
	for _, pair := range scaPairs {
		t.Run(pair.name, func(t *testing.T) {
			got := failingChecks(t, parseSCA(t, filepath.Join(scaDir, pair.full)), bundle)
			if !equalInts(got, want[pair.name]) {
				t.Errorf("the full %s policy fails checks %v on the M0 bundle, want %v.\n"+
					"If the M0 bundle now carries enforcement keys, the M0 policies and docs/06 blocker 1 are out of date; "+
					"if a check changed, decide whether the M0 subset should follow", pair.name, got, want[pair.name])
			}
		})
	}
}

func TestM0PoliciesPassTheM0BundleAndDropNothingItCouldKeep(t *testing.T) {
	bundle := loadBundle(t)
	for _, pair := range scaPairs {
		t.Run(pair.name, func(t *testing.T) {
			full := parseSCA(t, filepath.Join(scaDir, pair.full))
			m0 := parseSCA(t, filepath.Join(scaDir, pair.m0))

			if failing := failingChecks(t, m0, bundle); len(failing) != 0 {
				t.Errorf("the M0 %s policy asserts checks %v that the M0 bundle does not satisfy: D12 would fire on every endpoint", pair.name, failing)
			}

			// And the other direction: the M0 policy is exactly the full policy minus what the
			// bundle fails. Dropping a check the bundle passes would silently shrink D12.
			var want []int
			failed := map[int]bool{}
			for _, id := range failingChecks(t, full, bundle) {
				failed[id] = true
			}
			for _, id := range full.order {
				if !failed[id] {
					want = append(want, id)
				}
			}
			sort.Ints(want)
			got := append([]int(nil), m0.order...)
			sort.Ints(got)
			if !equalInts(got, want) {
				t.Errorf("the M0 %s policy has checks %v, want %v (the full policy minus the checks the M0 bundle fails)", pair.name, got, want)
			}
		})
	}
}

// The manager rules key on the policy id and on check 10007 specifically. If either moved,
// the M0 policy would run and never alert, which looks exactly like a quiet fleet.
func TestM0PoliciesKeepTheIdentifiersTheManagerRulesMatch(t *testing.T) {
	var rulesText string
	paths, _ := filepath.Glob(rulesGlob)
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rulesText += string(raw)
	}
	idRe := regexp.MustCompile(`name="sca\.policy_id">([^<]+)<`)
	m := idRe.FindStringSubmatch(rulesText)
	if m == nil {
		t.Fatal("no rule matches on sca.policy_id any more; this test has nothing to pin")
	}
	pattern := regexp.MustCompile(m[1])
	if !strings.Contains(rulesText, `name="sca.check.id">^10007$`) {
		t.Fatal("no rule matches on sca.check.id 10007 any more; this test has nothing to pin")
	}
	for _, pair := range scaPairs {
		p := parseSCA(t, filepath.Join(scaDir, pair.m0))
		if !pattern.MatchString(p.policyID) {
			t.Errorf("%s: policy id %q does not match the manager rules' pattern %q", pair.m0, p.policyID, m[1])
		}
		if _, ok := p.checks[10007]; !ok {
			t.Errorf("%s: no check 10007, so D7's SCA half would never fire on an M0 endpoint", pair.m0)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
