package wazuh

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Wazuh alerts one rule per event, and which rule that is depends on the rules' levels and
// parents, not only on whether each rule's own conditions hold. matches() in rules_test.go
// answers the second question only, which is how rule 100247 passed every test while being
// unable to fire: it matched an event, but a sibling with a higher level always took it.
//
// winnerOf models the first question. The model comes from what wazuh-logtest did on the
// 4.14.8 image: among sibling rules that match, the level 0 ones are tried first and then the
// highest level, file order only breaks ties, and a matching child (if_sid) replaces its
// parent. TestWinnerModelAgreesWithWazuh checks the model against the recorded answers in
// fixtures/*.winners, so a wrong model fails there rather than quietly misleading the test
// that uses it.

const (
	matrixPath = "fixtures/d5-matrix.jsonl"
	alonePath  = "fixtures/rules-alone.jsonl"
)

// d5-matrix.jsonl is every MCP baseline state against most combinations of scan classes, one
// server per event so that no correlation rule fires. rules-alone.jsonl has one event for each
// rule that, in the other fixtures, only ever matches next to a higher-level rule.
var winnerFixtures = []string{fixturesPath, sweepsPath, matrixPath, alonePath}

func winnersFile(fixture string) string {
	return strings.TrimSuffix(fixture, ".jsonl") + ".winners"
}

// modelled reports whether the winner model covers a rule. Correlation rules are triggered by
// earlier alerts rather than competing for an event, and rules that read Wazuh's own alerts
// need the real engine.
func modelled(r rule) bool {
	return !r.isCorrelation() && !r.hasGroup(groupWazuhSourced)
}

func parentList(raw string) []int {
	var out []int
	for _, part := range strings.Split(raw, ",") {
		if id, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func childrenOf(rules []rule, id int) []rule {
	var out []rule
	for _, r := range rules {
		if !modelled(r) {
			continue
		}
		for _, p := range parentList(r.IfSID) {
			if p == id {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func siblingOrder(rs []rule) []rule {
	out := append([]rule(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Level == 0) != (b.Level == 0) {
			return a.Level == 0
		}
		return a.Level > b.Level
	})
	return out
}

func descend(cands []rule, rules []rule, byID map[int]rule, ev map[string]any) (int, bool) {
	for _, c := range siblingOrder(cands) {
		ok, err := matches(c, ev, byID)
		if err != nil || !ok {
			continue
		}
		if id, found := descend(childrenOf(rules, c.ID), rules, byID, ev); found {
			return id, true
		}
		return c.ID, true
	}
	return 0, false
}

func winnerOf(rules []rule, byID map[int]rule, ev map[string]any) (int, bool) {
	var roots []rule
	for _, r := range rules {
		if modelled(r) && strings.TrimSpace(r.IfSID) == "" {
			roots = append(roots, r)
		}
	}
	return descend(roots, rules, byID, ev)
}

func loadWinners(t *testing.T, fixture string) []int {
	t.Helper()
	raw, err := os.ReadFile(winnersFile(fixture))
	if err != nil {
		t.Fatalf("read %s: %v", winnersFile(fixture), err)
	}
	var out []int
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "-" {
			out = append(out, 0)
			continue
		}
		id, err := strconv.Atoi(line)
		if err != nil {
			t.Fatalf("%s: %q is neither a rule id nor -", winnersFile(fixture), line)
		}
		out = append(out, id)
	}
	return out
}

func indexRules(rules []rule) map[int]rule {
	byID := map[int]rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	return byID
}

func TestWinnerModelAgreesWithWazuh(t *testing.T) {
	rules := loadRules(t)
	byID := indexRules(rules)

	var compared int
	for _, fixture := range winnerFixtures {
		events := loadFixtureFile(t, fixture)
		recorded := loadWinners(t, fixture)
		if len(recorded) != len(events) {
			t.Fatalf("%s has %d lines but %s records %d winners; re-record the winners with wazuh-logtest on the 4.14.8 image (one process per fixture, one winner per line)",
				fixture, len(events), winnersFile(fixture), len(recorded))
		}
		for i, ev := range events {
			want := recorded[i]
			if want != 0 {
				if r, ok := byID[want]; !ok || !modelled(r) {
					continue
				}
			}
			got, _ := winnerOf(rules, byID, ev)
			compared++
			if got != want {
				t.Errorf("%s line %d: Wazuh alerted rule %d, the model picks %d; either the model is wrong or the rules changed since %s was recorded",
					fixture, i+1, want, got, winnersFile(fixture))
			}
		}
	}
	if compared < 100 {
		t.Errorf("only %d events were comparable; the model is not being exercised", compared)
	}
}

// knownUnreachable lists rules that match fixture events but never win one. Each entry is a
// defect to fix, not a feature: delete the entry when the rule is made reachable, and the test
// fails if an entry starts winning so the list cannot go stale.
var knownUnreachable = map[int]string{}

func TestEveryRuleThatMatchesAFixtureCanAlsoWinOne(t *testing.T) {
	rules := loadRules(t)
	byID := indexRules(rules)

	won := map[int]bool{}
	matched := map[int]bool{}
	for _, fixture := range winnerFixtures {
		for _, ev := range loadFixtureFile(t, fixture) {
			if id, ok := winnerOf(rules, byID, ev); ok {
				won[id] = true
			}
			for _, r := range rules {
				if !modelled(r) || r.hasGroup(groupPendingEmitter) {
					continue
				}
				if ok, err := matches(r, ev, byID); err == nil && ok {
					matched[r.ID] = true
				}
			}
		}
	}

	var ids []int
	for id := range matched {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		reason, listed := knownUnreachable[id]
		switch {
		case !won[id] && !listed:
			t.Errorf("rule %d matches fixture events but never wins one. Either it is unreachable (a sibling with a higher level, or an earlier one at the same level, takes every event it matches: make it a child of that rule with if_sid, as 100247 is of 100241) or no fixture shows it alone. Try an event where it should win under wazuh-logtest, and add it to %s with its recorded winner", id, alonePath)
		case won[id] && listed:
			t.Errorf("rule %d now wins a fixture event; remove it from knownUnreachable (%s)", id, reason)
		}
	}
	for id := range knownUnreachable {
		if !matched[id] {
			t.Errorf("knownUnreachable lists rule %d, which matches no fixture event", id)
		}
	}
	if len(won) == 0 {
		t.Fatal(fmt.Sprintf("no rule won any of %d fixture files", len(winnerFixtures)))
	}
}

func TestWinnerFixturesStayInsideTheFieldBudget(t *testing.T) {
	for _, path := range []string{matrixPath, alonePath} {
		for i, ev := range loadFixtureFile(t, path) {
			if len(ev) > fieldBudget {
				t.Errorf("%s line %d has %d fields, budget is %d: an event this wide risks the decoder rejecting it, which is silent detection loss", path, i+1, len(ev), fieldBudget)
			}
		}
	}
}

func TestApprovedHiddenInstructionRuleIsAChildOfTheConcealedInstructionRule(t *testing.T) {
	byID := indexRules(loadRules(t))
	child, ok := byID[100247]
	if !ok {
		t.Fatal("rule 100247 is gone; if it was retired on purpose, update this test and the D5 runbook")
	}
	if got := strings.TrimSpace(child.IfSID); got != "100241" {
		t.Errorf("rule 100247 has if_sid %q; it must be a child of 100241. As a sibling at level %d behind 100241 at level %d it can never win: wazuh-logtest on 4.14.8 alerted an approved tool with hidden_instruction as 100241", got, child.Level, byID[100241].Level)
	}
}

func TestHiddenInstructionCorrelationCountsEveryRuleThatReportsIt(t *testing.T) {
	rules := loadRules(t)
	byID := indexRules(rules)
	corr := byID[100248]
	if corr.IfMatchedSI != "" || strings.TrimSpace(corr.IfMatchedGr) != "ambit_d5_hidden" {
		t.Errorf("rule 100248 counts if_matched_sid=%q if_matched_group=%q; it must count the group ambit_d5_hidden, because an approved tool's concealed instruction alerts as 100247, not 100241, and a count on 100241 alone would never see it",
			corr.IfMatchedSI, corr.IfMatchedGr)
	}
	var carriers []int
	for _, r := range rules {
		if r.hasExactGroup("ambit_d5_hidden") {
			carriers = append(carriers, r.ID)
		}
	}
	sort.Ints(carriers)
	if fmt.Sprint(carriers) != "[100241 100247]" {
		t.Errorf("rules carrying group ambit_d5_hidden: %v; want exactly [100241 100247], the two rules that report a concealed instruction", carriers)
	}
}
