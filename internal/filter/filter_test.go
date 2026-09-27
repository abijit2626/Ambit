package filter

import (
	"testing"

	"github.com/abijit2626/indirect-prompt/internal/classify"
	"github.com/abijit2626/indirect-prompt/internal/event"
)

// neverSample makes the sampled-remainder path deterministic so tests measure
// the interesting criteria and nothing else.
func testFilter() *Filter {
	cfg := DefaultConfig()
	cfg.TrustedMCPServers = map[string]bool{"internal-wiki": true}
	return NewWithSampler(cfg, func() float64 { return 1.0 })
}

func toolEvent(mut func(*event.Event)) *event.Event {
	e := &event.Event{
		Kind: event.KindToolPre,
		Tool: &event.Tool{
			Name:  "Read",
			Paths: []event.PathRef{{Zone: event.ZoneWorkdir, Op: "read", PathDigest: "hmac:x"}},
		},
	}
	if mut != nil {
		mut(e)
	}
	return e
}

func TestOrdinaryToolCallDoesNotCross(t *testing.T) {
	v := testFilter().Decide(toolEvent(nil))
	if v.Cross {
		t.Errorf("an ordinary workdir read crossed (%s); this is the firehose the filter exists to stop", v.Reason)
	}
}

func TestInterestingCriteria(t *testing.T) {
	yes := true
	cases := []struct {
		name       string
		mut        func(*event.Event)
		wantReason string
	}{
		{"deny decision", func(e *event.Event) { e.Policy.Decision = event.DecisionDeny }, ReasonDecision},
		{"ask decision", func(e *event.Event) { e.Policy.Decision = event.DecisionAsk }, ReasonDecision},
		{"fail open", func(e *event.Event) { e.Policy.Decision = event.DecisionFailOpen }, ReasonDecision},
		{"provenance edge", func(e *event.Event) {
			e.Provenance.Edges = []event.Edge{{MatchClass: "domain", Confidence: 0.9}}
		}, ReasonProvEdge},
		{"r2 transition", func(e *event.Event) { e.R2.Transition = true }, ReasonR2Transition},
		{"notable fingerprint", func(e *event.Event) { e.Provenance.FPNotable = "hmac:f" }, ReasonNotableFP},
		{"credential zone", func(e *event.Event) {
			e.Tool.Paths = []event.PathRef{{Zone: event.ZoneCredential, Op: "read"}}
		}, ReasonSevereZone},
		{"system zone", func(e *event.Event) {
			e.Tool.Paths = []event.PathRef{{Zone: event.ZoneSystem, Op: "read"}}
		}, ReasonSevereZone},
		{"secret hit", func(e *event.Event) {
			e.Tool.InputFeatures = &event.Features{SecretHits: []event.SecretHit{{Kind: "aws_key", Count: 1}}}
		}, ReasonSecretHit},
		{"network command", func(e *event.Event) {
			e.Tool.Bash = &event.Bash{Argv0: "curl", CommandClass: classify.ClassNetwork}
		}, ReasonNetworkCmd},
		{"git push", func(e *event.Event) {
			e.Tool.Bash = &event.Bash{Argv0: "git", CommandClass: classify.ClassVCSWrite}
		}, ReasonNetworkCmd},
		{"destructive mcp", func(e *event.Event) {
			e.Tool.MCP = &event.MCP{Server: "internal-wiki", Annotations: event.Annotations{DestructiveHint: &yes}}
		}, ReasonMCPRisk},
		{"unclassified mcp server", func(e *event.Event) {
			e.Tool.MCP = &event.MCP{Server: "some-external-server"}
		}, ReasonMCPRisk},
	}

	f := testFilter()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := f.Decide(toolEvent(c.mut))
			if !v.Cross {
				t.Fatalf("event did not cross, want reason %q", c.wantReason)
			}
			if v.Reason != c.wantReason {
				t.Errorf("reason = %q, want %q", v.Reason, c.wantReason)
			}
		})
	}
}

// TestR2SteadyStateDoesNotCross: only the transition is interesting. If every
// event after the first untrusted fetch crossed, one web page would make the
// rest of a session unconditionally interesting.
func TestR2SteadyStateDoesNotCross(t *testing.T) {
	e := toolEvent(func(e *event.Event) {
		e.R2 = event.R2{A: true, B: true, C: false, Transition: false}
	})
	if v := testFilter().Decide(e); v.Cross {
		t.Errorf("steady-state R2 event crossed (%s); only transitions should", v.Reason)
	}
}

// TestFilterNeverRelaxesOnServerClaim is the annotation-asymmetry guard: an
// untrusted server asserting readOnlyHint must not stop its events crossing.
func TestFilterNeverRelaxesOnServerClaim(t *testing.T) {
	yes := true
	e := toolEvent(func(e *event.Event) {
		e.Tool.MCP = &event.MCP{
			Server:      "some-external-server",
			Annotations: event.Annotations{ReadOnlyHint: &yes},
		}
	})
	if v := testFilter().Decide(e); !v.Cross {
		t.Error("a server claiming readOnlyHint suppressed its own events; annotations may only make policy stricter")
	}
}

func TestTrustedMCPServerIsNotInterestingByItself(t *testing.T) {
	e := toolEvent(func(e *event.Event) { e.Tool.MCP = &event.MCP{Server: "internal-wiki", Tool: "search"} })
	if v := testFilter().Decide(e); v.Cross {
		t.Errorf("an explicitly trusted server's ordinary call crossed (%s)", v.Reason)
	}
}

func TestAlwaysCrossKinds(t *testing.T) {
	f := testFilter()
	for _, k := range []event.Kind{
		event.KindSessionStart, event.KindSessionEnd, event.KindToolFail,
		event.KindPermissionDenied, event.KindInstructionsLoaded,
		event.KindConfigChange, event.KindFileChanged, event.KindMCPList,
		event.KindSubagentStart, event.KindSubagentStop, event.KindCompact,
		event.KindAgentdHealth, event.KindPromptSubmit,
	} {
		if v := f.Decide(&event.Event{Kind: k}); !v.Cross {
			t.Errorf("kind %q did not cross but is a detector input", k)
		}
	}
}

// TestUnknownKindCrosses: failing open on volume is recoverable; a new event
// kind silently not reaching the SIEM is a detection gap nobody notices.
func TestUnknownKindCrosses(t *testing.T) {
	if v := testFilter().Decide(&event.Event{Kind: event.Kind("some_future_kind")}); !v.Cross {
		t.Error("an unrecognized kind should cross rather than vanish")
	}
}

func TestGoalDriftThreshold(t *testing.T) {
	f := testFilter()
	low, high := 0.2, 0.95
	if v := f.Decide(&event.Event{Kind: event.KindGoalDriftScore, Scores: event.Scores{GoalDrift: &low}}); v.Cross {
		t.Error("a low drift score should stay in the spool")
	}
	v := f.Decide(&event.Event{Kind: event.KindGoalDriftScore, Scores: event.Scores{GoalDrift: &high}})
	if !v.Cross || v.Reason != ReasonDriftAbove {
		t.Errorf("high drift score: cross=%v reason=%q, want true/%q", v.Cross, v.Reason, ReasonDriftAbove)
	}
	if v := f.Decide(&event.Event{Kind: event.KindGoalDriftScore}); v.Cross {
		t.Error("a drift event with no score should not cross")
	}
}

func TestSampledRemainder(t *testing.T) {
	cfg := DefaultConfig()
	// Sampler always returns below the rate, so the remainder always crosses.
	f := NewWithSampler(cfg, func() float64 { return 0.0 })
	v := f.Decide(toolEvent(nil))
	if !v.Cross || v.Reason != ReasonSampled {
		t.Errorf("cross=%v reason=%q, want true/%q", v.Cross, v.Reason, ReasonSampled)
	}

	// Rate 0 disables sampling entirely.
	cfg.SampleRate = 0
	f2 := NewWithSampler(cfg, func() float64 { return 0.0 })
	if v := f2.Decide(toolEvent(nil)); v.Cross {
		t.Errorf("SampleRate 0 should disable the remainder, got %q", v.Reason)
	}
}

// TestInterestingFractionIsPlausible approximates the M0 exit criterion: on a
// synthetic mix resembling ordinary work, the crossing fraction should land near
// the 2-5% the design estimates. This is a smoke test on the criteria, not a
// measurement — the real number comes from a cohort, and if it comes back far
// from this the criteria tighten.
func TestInterestingFractionIsPlausible(t *testing.T) {
	f := testFilter()
	const n = 10000
	crossed := 0
	for i := 0; i < n; i++ {
		e := toolEvent(nil)
		switch {
		case i%200 == 0: // credential read
			e.Tool.Paths = []event.PathRef{{Zone: event.ZoneCredential, Op: "read"}}
		case i%150 == 0: // network command
			e.Tool.Bash = &event.Bash{Argv0: "curl", CommandClass: classify.ClassNetwork}
		case i%500 == 0: // r2 transition
			e.R2.Transition = true
		}
		if f.Decide(e).Cross {
			crossed++
		}
	}
	frac := float64(crossed) / n
	if frac > 0.10 {
		t.Errorf("crossing fraction %.3f exceeds 10%%; the filter is too permissive to protect the indexer", frac)
	}
	t.Logf("synthetic crossing fraction: %.3f%%", frac*100)
}
