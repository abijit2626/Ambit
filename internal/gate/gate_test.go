package gate

import (
	"testing"

	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/r2"
)

var (
	none = r2.Bits{}
	a    = r2.Bits{A: true}
	b    = r2.Bits{B: true}
	ab   = r2.Bits{A: true, B: true}
	ac   = r2.Bits{A: true, C: true}
	abc  = r2.Bits{A: true, B: true, C: true}
)

func TestEachRowFiresOnlyWhenItsPreconditionHolds(t *testing.T) {
	cases := []struct {
		name   string
		prior  r2.Bits
		action Action
		want   event.Decision
		rule   string
	}{
		// Credential read: needs A before it.
		{"credential read after A", a, Action{CredentialRead: true, Bits: b}, event.DecisionDeny, RuleCredentialAfterA},
		{"credential read with no prior A", none, Action{CredentialRead: true, Bits: b}, event.DecisionNone, ""},

		// Push or publish: needs A and B.
		{"push after A and B", ab, Action{BashClass: classify.ClassVCSWrite, Bits: ac}, event.DecisionAsk, RulePublishAfterAB},
		{"publish after A and B", ab, Action{BashClass: classify.ClassPublish, Bits: ac}, event.DecisionAsk, RulePublishAfterAB},
		{"push after A only", a, Action{BashClass: classify.ClassVCSWrite, Bits: ac}, event.DecisionNone, ""},

		// Other outbound network: needs A and B.
		{"curl after A and B", ab, Action{BashClass: classify.ClassNetwork, Bits: ac}, event.DecisionDeny, RuleEgressAfterAB},
		{"curl after B only", b, Action{BashClass: classify.ClassNetwork, Bits: ac}, event.DecisionAllowAlert, RuleTrifecta},
		{"non-network bash after A and B", ab, Action{BashClass: classify.ClassFilesystem}, event.DecisionNone, ""},

		// Write outside the working directory: needs A and B.
		{"write outside after A and B", ab, Action{WriteOutside: true, Bits: r2.Bits{C: true}}, event.DecisionAsk, RuleWriteOutsideAB},
		{"write outside after A only", a, Action{WriteOutside: true, Bits: r2.Bits{C: true}}, event.DecisionNone, ""},

		// Unclassified MCP server: needs A and B.
		{"mcp call after A and B", ab, Action{MCPUnclassified: true, Bits: ac}, event.DecisionAsk, RuleMCPAfterAB},
		{"mcp call after A only", a, Action{MCPUnclassified: true, Bits: ac}, event.DecisionNone, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Evaluate(c.prior, c.action)
			if v.Decision != c.want || v.RuleID != c.rule {
				t.Errorf("verdict = %q %q, want %q %q", v.Decision, v.RuleID, c.want, c.rule)
			}
			if v.Fired() && v.Reason == "" {
				t.Error("a verdict with no reason is one nobody can triage")
			}
		})
	}
}

// A push is also network-capable. docs/03 asks for ask, not deny, for a push or publish, so
// the more specific row must win.
func TestPublishOutranksTheGeneralNetworkRow(t *testing.T) {
	if !classify.IsNetworkClass(classify.ClassVCSWrite) {
		t.Fatal("test premise broken: a push is no longer network-class, so the precedence is untested")
	}
	if v := Evaluate(ab, Action{BashClass: classify.ClassVCSWrite}); v.RuleID != RulePublishAfterAB {
		t.Errorf("push after A and B = %s, want %s", v.RuleID, RulePublishAfterAB)
	}
}

// "Everything else" alerts on the action that completes the trifecta, not on every later
// action in a session that already holds all three bits.
func TestTrifectaAlertsOnlyOnTheTransition(t *testing.T) {
	if v := Evaluate(ac, Action{Bits: b}); v.Decision != event.DecisionAllowAlert || v.RuleID != RuleTrifecta {
		t.Errorf("completing the trifecta = %+v, want allow_alert", v)
	}
	if v := Evaluate(abc, Action{Bits: a}); v.Fired() {
		t.Errorf("a further bit-setting action in a saturated session = %+v; it would alert on every call", v)
	}
	if v := Evaluate(ab, Action{}); v.Fired() {
		t.Errorf("an action contributing nothing = %+v, want no decision", v)
	}
}

// The specific rows are not transitions: a second exfiltration attempt in a saturated
// session must be denied just like the first.
func TestRowsStillFireInASaturatedSession(t *testing.T) {
	if v := Evaluate(abc, Action{BashClass: classify.ClassNetwork, Bits: ac}); v.Decision != event.DecisionDeny {
		t.Errorf("curl in a saturated session = %+v, want deny", v)
	}
}

func TestNoDecisionWithoutPriorBits(t *testing.T) {
	for _, act := range []Action{
		{CredentialRead: true, Bits: b},
		{BashClass: classify.ClassNetwork, Bits: ac},
		{WriteOutside: true, Bits: r2.Bits{C: true}},
		{MCPUnclassified: true, Bits: ac},
	} {
		if v := Evaluate(none, act); v.Fired() {
			t.Errorf("%+v on a fresh session = %+v, want nothing", act, v)
		}
	}
}

func TestActionFromReadsTheEvent(t *testing.T) {
	tool := &event.Tool{
		Paths: []event.PathRef{
			{Zone: event.ZoneCredential, Op: "read"},
			{Zone: event.ZoneHome, Op: "write"},
		},
		Bash: &event.Bash{CommandClass: classify.ClassNetwork},
		MCP:  &event.MCP{Server: "github"},
	}
	got := ActionFrom(tool, ac)
	if !got.CredentialRead || !got.WriteOutside || got.BashClass != classify.ClassNetwork || !got.MCPUnclassified || got.Bits != ac {
		t.Errorf("ActionFrom = %+v", got)
	}

	// A write inside the working directory, or to a path the zoner could not place, is not
	// "outside": the same rule internal/r2 applies to bit C.
	for _, z := range []string{event.ZoneWorkdir, event.ZoneUnknown} {
		if ActionFrom(&event.Tool{Paths: []event.PathRef{{Zone: z, Op: "write"}}}, none).WriteOutside {
			t.Errorf("a write in zone %q counted as outside the working directory", z)
		}
	}
	// A server the operator classified internal is not unclassified.
	if ActionFrom(&event.Tool{MCP: &event.MCP{Server: "wiki", Trust: "internal"}}, none).MCPUnclassified {
		t.Error("an internal MCP server counted as unclassified")
	}
	if got := ActionFrom(nil, a); got.Bits != a {
		t.Errorf("ActionFrom(nil) = %+v", got)
	}
}
