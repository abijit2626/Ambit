package collector

import (
	"strings"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/hook"
)

const (
	violationsOpen  = "<sandbox_violations>"
	violationsClose = "</sandbox_violations>"

	maxDenials = 32
	maxOpLen   = 40
)

type denial struct{ op, target string }

// sandboxDenials reads the <sandbox_violations> block Claude Code appends to a sandboxed command's error,
// one "deny <op> <target> (<reason>)" per line (observed on v2.1.310 as
// "deny network-outbound example.com:443 (user denied)"). Only the last block counts, because Claude
// Code appends its own after the command's output; a command can still print a block of its own, so a
// denial is the command output's claim, not the sandbox's.
func sandboxDenials(text string) []denial {
	i := strings.LastIndex(text, violationsOpen)
	if i < 0 {
		return nil
	}
	body := text[i+len(violationsOpen):]
	if j := strings.Index(body, violationsClose); j >= 0 {
		body = body[:j]
	}
	var out []denial
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "deny ")
		if !ok {
			continue
		}
		op, target, _ := strings.Cut(rest, " ")
		if k := strings.LastIndex(target, " ("); k >= 0 && strings.HasSuffix(target, ")") {
			target = target[:k]
		}
		out = append(out, denial{op: cleanOp(op), target: strings.TrimSpace(target)})
		if len(out) == maxDenials {
			break
		}
	}
	return out
}

// cleanOp keeps an op only if it looks like one of Claude Code's (lowercase letters and hyphens), so a
// forged block cannot carry arbitrary text to the SIEM in cleartext.
func cleanOp(op string) string {
	if op == "" || len(op) > maxOpLen {
		return "other"
	}
	for _, r := range op {
		if (r < 'a' || r > 'z') && r != '-' {
			return "other"
		}
	}
	return op
}

// emitSandboxDenial sends a sandbox_denial event for a failed or finished tool call whose output carries a
// <sandbox_violations> block. It is not retried if the sink refuses it: the tool event itself is in the
// spool with the block in its error.
func (c *Collector) emitSandboxDenial(st *sessionState, p *hook.Payload, e *event.Event) {
	ds := toolDenials(p, e)
	if len(ds) == 0 {
		return
	}
	d := &event.SandboxDenial{}
	seenOp := map[string]bool{}
	for _, x := range ds {
		if !seenOp[x.op] {
			seenOp[x.op] = true
			d.Ops = append(d.Ops, x.op)
		}
		if x.target != "" {
			d.TargetDigests = append(d.TargetDigests, c.ext.Digest(x.target))
		}
	}

	n := derivedFrom(st, e, event.KindSandboxDenial)
	n.Denial = d
	c.emitDerived(n)
}

// toolDenials is the sandbox's refusals for a failed or finished tool call, read from the failure, or
// from the output when the failure carries no block.
func toolDenials(p *hook.Payload, e *event.Event) []denial {
	if e.Kind != event.KindToolFail && e.Kind != event.KindToolPost {
		return nil
	}
	text := p.ToolFailure()
	if !strings.Contains(text, violationsOpen) {
		out, _ := p.ToolOutput()
		text = out
	}
	return sandboxDenials(text)
}

// derivedFrom starts an event ambitd derives from e: the same endpoint, actor, agent and session, the
// next sequence number in the session, no policy decision, and only the tool's name and use id.
func derivedFrom(st *sessionState, e *event.Event, kind event.Kind) *event.Event {
	n := &event.Event{
		EventID:    newEventID(),
		TS:         e.TS,
		IngestedAt: e.IngestedAt,
		Source:     event.SourceAmbitd,
		SchemaV:    e.SchemaV,
		Kind:       kind,
		Endpoint:   e.Endpoint,
		Actor:      e.Actor,
		Agent:      e.Agent,
		Session:    event.Session{SessionID: e.Session.SessionID, PromptID: e.Session.PromptID, AgentID: e.Session.AgentID, AgentType: e.Session.AgentType},
		R2:         e.R2,
		Policy:     event.Policy{Decision: event.DecisionNone},
	}
	n.Session.Sequence = st.next()
	n.R2.Transition = false
	if e.Tool != nil {
		n.Tool = &event.Tool{Name: e.Tool.Name, UseID: e.Tool.UseID}
	}
	return n
}
