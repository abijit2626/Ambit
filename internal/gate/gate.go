// Package gate is the Rule-of-Two gate from docs/03-detection.md, Layer 1: the verdict
// on a PreToolUse given what the session has already done.
//
// In M2 it runs in shadow mode. The verdict is computed on every PreToolUse and recorded on
// the event, and it is never returned to Claude Code: the hook's decider stays
// hook.ObserveOnly and every response stays {}. Shadow mode exists to answer, with data,
// the two questions docs/03 says must not be settled by argument: how often each row would
// fire on real sessions, and which session scoping keeps it usable. A deny that would have
// stopped a developer mid-task fleet-wide is exactly what this measures before anyone
// enforces it.
//
// The table, in order (the first matching row wins):
//
//	| Action class                                | Session already holds | Decision    |
//	| Credential-path read                        | A                     | deny        |
//	| git push / package publish                  | A and B               | ask         |
//	| Any other outbound network from Bash        | A and B               | deny        |
//	| Write outside the working directory         | A and B               | ask         |
//	| Call to an MCP server not classified internal| A and B              | ask         |
//	| Any action that completes A, B and C        | not all three         | allow_alert |
//
// Two readings of the table in docs/03 are decisions, recorded here so they are not
// silently assumed:
//
//   - "after A" means the session held A BEFORE this action. A curl sets bit A through its
//     own output, but the rule is about acting after untrusted input has arrived, not about
//     the action's own result.
//   - The listed rows fire whenever their precondition holds. "Everything else" (allow and
//     alert) fires only on the action that completes the trifecta, not on every later
//     action in a session that already has all three bits; otherwise a long session would
//     alert on every tool call, which is the firehose docs/04 exists to prevent.
//
// The publish row precedes the general network row because a push or a publish is also
// network-capable, and docs/03 asks for ask, not deny, for those.
package gate

import (
	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/r2"
)

// BundleVersion identifies this rule table in policy.bundle_version. M3's signed policy
// bundles replace it; until then a change to the table must change this string, so a
// verdict in the SIEM can always be traced to the rules that produced it.
const BundleVersion = "r2-gate.v1"

// Rule ids, carried in policy.rule_ids and flattened to policy_rule_id.
const (
	RuleCredentialAfterA = "r2.credential_after_a"
	RulePublishAfterAB   = "r2.publish_after_ab"
	RuleEgressAfterAB    = "r2.egress_after_ab"
	RuleWriteOutsideAB   = "r2.write_outside_after_ab"
	RuleMCPAfterAB       = "r2.mcp_after_ab"
	RuleTrifecta         = "r2.trifecta"
)

// Action is what the gate needs to know about one tool call. It is built from the event the
// collector has already constructed (ActionFrom), so the gate adds no classification of its
// own and cannot disagree with Rule-of-Two accounting about what an action is.
type Action struct {
	// Bits is the action's own Rule-of-Two contribution.
	Bits r2.Bits
	// CredentialRead: a read of a path in the credential zone.
	CredentialRead bool
	// WriteOutside: a write to a path outside the working directory. A path the zoner could
	// not place (zone unknown) is not counted, the same rule internal/r2 applies.
	WriteOutside bool
	// BashClass is the Bash command class, empty for any other tool.
	BashClass string
	// MCPUnclassified: a call to an MCP server the operator has not classified internal.
	MCPUnclassified bool
}

// ActionFrom describes a tool event for the gate.
func ActionFrom(t *event.Tool, bits r2.Bits) Action {
	a := Action{Bits: bits}
	if t == nil {
		return a
	}
	for _, p := range t.Paths {
		if p.Zone == event.ZoneCredential && p.Op == "read" {
			a.CredentialRead = true
		}
		if p.Op == "write" && p.Zone != event.ZoneWorkdir && p.Zone != event.ZoneUnknown {
			a.WriteOutside = true
		}
	}
	if t.Bash != nil {
		a.BashClass = t.Bash.CommandClass
	}
	if t.MCP != nil && t.MCP.Trust != "internal" {
		a.MCPUnclassified = true
	}
	return a
}

// Verdict is the gate's decision for one action. The zero value is "no decision".
type Verdict struct {
	Decision event.Decision
	RuleID   string
	Reason   string
}

// Fired reports whether any row matched.
func (v Verdict) Fired() bool { return v.Decision != event.DecisionNone }

// Evaluate returns the verdict for an action, given the bits the session (or whichever
// scoping the caller is measuring) held before it.
func Evaluate(prior r2.Bits, a Action) Verdict {
	ab := prior.A && prior.B

	switch {
	case prior.A && a.CredentialRead:
		return Verdict{event.DecisionDeny, RuleCredentialAfterA,
			"credential-path read after untrusted input"}
	case ab && (a.BashClass == classify.ClassPublish || a.BashClass == classify.ClassVCSWrite):
		return Verdict{event.DecisionAsk, RulePublishAfterAB,
			"push or publish after untrusted input and sensitive data"}
	case ab && classify.IsNetworkClass(a.BashClass):
		return Verdict{event.DecisionDeny, RuleEgressAfterAB,
			"outbound network from Bash after untrusted input and sensitive data"}
	case ab && a.WriteOutside:
		return Verdict{event.DecisionAsk, RuleWriteOutsideAB,
			"write outside the working directory after untrusted input and sensitive data"}
	case ab && a.MCPUnclassified:
		return Verdict{event.DecisionAsk, RuleMCPAfterAB,
			"call to an unclassified MCP server after untrusted input and sensitive data"}
	}

	after := prior.Or(a.Bits)
	if all(after) && !all(prior) {
		return Verdict{event.DecisionAllowAlert, RuleTrifecta,
			"this action completes untrusted input, sensitive data and external action in one session"}
	}
	return Verdict{}
}

func all(b r2.Bits) bool { return b.A && b.B && b.C }
