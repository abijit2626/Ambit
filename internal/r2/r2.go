// Package r2 classifies a single event against Meta's Agents Rule of Two
// (31 October 2025): of three properties — untrusted input ingested (A),
// sensitive data accessed (B), state change or external communication (C) —
// an autonomous agent should satisfy no more than two within a session.
//
// This package answers "what does this one event contribute", nothing more.
// It does not accumulate bits across a session, and it does not decide what a
// "session" is for that accumulation — that is internal/collector's
// sessionState and docs/07-open-questions.md Q1's open question,
// respectively. The split is deliberate: these rules should be testable
// without a fake session, and a future change to session scoping (Q1 options
// 3 or 4, chosen from the shadow-mode data this package's output feeds) should
// touch the accumulator, never these classification rules.
//
// Every rule here mirrors one bullet in docs/03-detection.md's Layer 1,
// deliberately literally rather than narrowed by judgment calls this package
// has no business making — including the ones that read as overly broad on a
// long session. That breadth is the known problem Q1 exists to solve with
// measured data, not something to paper over here.
//
// Two of docs/03's bullets are not implemented, and are not silently dropped:
//
//   - "Any tool annotated openWorldHint: true" needs MCP annotations joined
//     onto tool CALL events. Only the interposer's LISTING events carry
//     annotations today (docs/03's "What writing the rules exposed" records
//     this as a standing gap); the practical fallback docs/03 itself states —
//     treat every non-internal-server MCP tool as both ingest and egress — is
//     what ClassifyTool implements instead, so no signal is lost, only its
//     precision.
//   - "An MCP tool returning data from a system labelled sensitive" needs a
//     sensitivity classification beyond the existing trust label. No such
//     classification exists in configuration; adding one speculatively, ahead
//     of a real need for it, is not this package's call to make.
package r2

import (
	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
)

// Bits is one event's contribution. Not cumulative — the caller ORs this into
// session state.
type Bits struct {
	A, B, C bool
}

// Or returns the union of two Bits.
func (b Bits) Or(other Bits) Bits {
	return Bits{A: b.A || other.A, B: b.B || other.B, C: b.C || other.C}
}

// Any reports whether any bit is set.
func (b Bits) Any() bool { return b.A || b.B || b.C }

// ToolInput is the subset of an already-built event.Tool that ClassifyTool
// reads, plus WebUntrusted — the one signal docs/03's bit A needs that
// event.Tool itself does not carry.
//
// Deliberately built from fields the collector has already computed rather
// than reparsing anything: this package adds no path classification, no bash
// parsing, and no digesting of its own.
type ToolInput struct {
	ToolName string
	Paths    []event.PathRef
	Bash     *event.Bash
	MCP      *event.MCP
	// SecretHitCount should be the count AFTER the collector has merged
	// result-side secret hits into the input-side set (internal/collector
	// does this before calling in), so a secret surfacing only in a tool's
	// OUTPUT still sets bit B.
	SecretHitCount int
	// WebUntrusted is true when ToolName is WebFetch or WebSearch and the
	// request's domain — or the absence of one this package could extract —
	// is not on the operator's trusted-content list. Resolved by the caller:
	// deciding it needs a digest comparison against configuration, which
	// needs the HMAC key this package deliberately does not hold. Keeping
	// keyed comparisons out of this package is the same discipline
	// internal/baseline documents for MetadataHash, applied here for the
	// opposite reason — that digest genuinely must not be keyed, and this one
	// genuinely must be, so neither choice belongs in code that has to make
	// neither.
	WebUntrusted bool
}

// ClassifyTool returns the Rule-of-Two contribution of one tool event.
//
// Call it once per PreToolUse and once per PostToolUse for the same call.
// The two calls are not redundant: PostToolUse additionally carries the
// tool's result, folded into SecretHitCount by the caller. Applying the same
// input-side bits twice is harmless under monotonic OR.
func ClassifyTool(in ToolInput) Bits {
	var b Bits

	for _, p := range in.Paths {
		switch p.Zone {
		case event.ZoneCredential:
			if p.Op == "read" {
				b.B = true // credential-path read
			}
		case event.ZoneUntrusted:
			if p.Op == "read" {
				b.A = true // dependency/vendor/downloads content ingested
			}
		}
		// "Read outside the working-directory boundary" (B) and "Write/Edit
		// outside the working directory" (C) are stated with no further
		// qualification in docs/03 — implemented literally. ZoneUnknown is
		// excluded because an unclassifiable path (no home or workdir
		// configured, or a path the zoner could not place) asserts nothing
		// about the boundary either way; treating "unknown" as "outside"
		// would manufacture a signal docs/03 never claimed to have.
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
		b.A = true // the round trip's output is untrusted ingest...
		b.C = true // ...and the round trip is itself the egress action.
	}

	if in.MCP != nil && in.MCP.Trust != "internal" {
		// A server merely claiming readOnlyHint earns no relaxation
		// (docs/02's asymmetry), and annotations are not on call events yet
		// (see the package doc). The fallback docs/03 itself states: treat
		// every non-internal MCP tool as both ingest and egress until an
		// operator has explicitly classified the server.
		b.A = true
		b.C = true
	}

	if isWebTool(in.ToolName) && in.WebUntrusted {
		b.A = true
	}

	return b
}

// ClassifyInstructionsLoaded returns the contribution of an InstructionsLoaded
// event: a CLAUDE.md or .claude/rules file read from outside the operator's
// trusted-repo list is untrusted input, full stop — docs/03 bit A, fourth
// bullet.
func ClassifyInstructionsLoaded(trustedRepo bool) Bits {
	return Bits{A: !trustedRepo}
}

func isWebTool(name string) bool {
	return name == "WebFetch" || name == "WebSearch"
}
