package gate

import (
	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/r2"
)

const BundleVersion = "r2-gate.v1"

const (
	RuleCredentialAfterA = "r2.credential_after_a"
	RulePublishAfterAB   = "r2.publish_after_ab"
	RuleEgressAfterAB    = "r2.egress_after_ab"
	RuleWriteOutsideAB   = "r2.write_outside_after_ab"
	RuleMCPAfterAB       = "r2.mcp_after_ab"
	RuleTrifecta         = "r2.trifecta"
)

type Action struct {
	Bits r2.Bits

	CredentialRead bool

	WriteOutside bool

	BashClass string

	MCPMayAct bool
}

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
	if m := t.MCP; m != nil {
		if m.Classified {
			a.MCPMayAct = !containsLabel(m.Labels, "read_only")
		} else {
			a.MCPMayAct = m.Trust != "internal"
		}
	}
	return a
}

type Verdict struct {
	Decision event.Decision
	RuleID   string
	Reason   string
}

func (v Verdict) Fired() bool { return v.Decision != event.DecisionNone }

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
	case ab && a.MCPMayAct:
		return Verdict{event.DecisionAsk, RuleMCPAfterAB,
			"MCP call that can act, after untrusted input and sensitive data"}
	}

	after := prior.Or(a.Bits)
	if all(after) && !all(prior) {
		return Verdict{event.DecisionAllowAlert, RuleTrifecta,
			"this action completes untrusted input, sensitive data and external action in one session"}
	}
	return Verdict{}
}

func all(b r2.Bits) bool { return b.A && b.B && b.C }

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
