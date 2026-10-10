package r2

import (
	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
)

type Bits struct {
	A, B, C bool
}

func (b Bits) Or(other Bits) Bits {
	return Bits{A: b.A || other.A, B: b.B || other.B, C: b.C || other.C}
}

func (b Bits) Any() bool { return b.A || b.B || b.C }

type ToolInput struct {
	ToolName string
	Paths    []event.PathRef
	Bash     *event.Bash
	MCP      *event.MCP

	SecretHitCount int

	WebUntrusted bool
}

func ClassifyTool(in ToolInput) Bits {
	var b Bits

	for _, p := range in.Paths {
		switch p.Zone {
		case event.ZoneCredential:
			if p.Op == "read" {
				b.B = true
			}
		case event.ZoneUntrusted:
			if p.Op == "read" {
				b.A = true
			}
		}

		if p.Zone != event.ZoneWorkdir && p.Zone != event.ZoneUnknown {
			switch p.Op {
			case "read":
				b.B = true
			case "write":
				b.C = true
			}
		}
	}

	if in.SecretHitCount > 0 {
		b.B = true
	}

	if in.Bash != nil && classify.IsNetworkClass(in.Bash.CommandClass) {
		b.A = true
		b.C = true
	}

	if in.MCP != nil && in.MCP.Classified {

		b.A = b.A || hasLabel(in.MCP.Labels, "untrusted")
		b.B = b.B || hasLabel(in.MCP.Labels, "sensitive")
		b.C = b.C || !hasLabel(in.MCP.Labels, "read_only")
	} else if in.MCP != nil && in.MCP.Trust != "internal" {

		b.A = true
		b.C = true
	}

	if isWebTool(in.ToolName) && in.WebUntrusted {
		b.A = true
	}

	return b
}

func ClassifyInstructionsLoaded(trustedRepo bool) Bits {
	return Bits{A: !trustedRepo}
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

func isWebTool(name string) bool {
	return name == "WebFetch" || name == "WebSearch"
}
