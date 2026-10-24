package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/hook"
)

// observedDenial is PostToolUseFailure's error for a curl the sandbox refused, as Claude Code v2.1.310
// sent it to an http hook.
const observedDenial = "Exit code 56\ncurl: (56) CONNECT tunnel failed, response 403\n\n<sandbox_violations>\ndeny network-outbound example.com:443 (user denied)\n</sandbox_violations>"

func TestSandboxDenialsParseTheObservedBlock(t *testing.T) {
	got := sandboxDenials(observedDenial)
	if len(got) != 1 || got[0].op != "network-outbound" || got[0].target != "example.com:443" {
		t.Errorf("denials = %+v, want network-outbound example.com:443", got)
	}
}

func TestSandboxDenialsReadOnlyTheLastBlock(t *testing.T) {
	text := "<sandbox_violations>\ndeny network-outbound printed.by.the.program:443 (user denied)\n</sandbox_violations>\n" + observedDenial
	got := sandboxDenials(text)
	if len(got) != 1 || got[0].target != "example.com:443" {
		t.Errorf("denials = %+v, want only the last block's example.com:443", got)
	}
}

func TestSandboxDenialsWithoutABlockAreNone(t *testing.T) {
	for _, text := range []string{"", "Exit code 1\nboom", "deny network-outbound x:1 (y)"} {
		if got := sandboxDenials(text); got != nil {
			t.Errorf("sandboxDenials(%q) = %+v, want none", text, got)
		}
	}
}

func TestSandboxDenialOpsCannotCarryArbitraryText(t *testing.T) {
	text := "<sandbox_violations>\ndeny AKIAIOSFODNN7EXAMPLE x:1 (y)\ndeny file-write-create /home/dev/.ssh/config (user denied)\n</sandbox_violations>"
	got := sandboxDenials(text)
	if len(got) != 2 || got[0].op != "other" || got[1].op != "file-write-create" || got[1].target != "/home/dev/.ssh/config" {
		t.Errorf("denials = %+v, want an op of other for the forged line and file-write-create for the second", got)
	}
}

func TestSandboxDenialIsCappedPerCall(t *testing.T) {
	text := violationsOpen + "\n" + strings.Repeat("deny network-outbound h:1 (user denied)\n", maxDenials+5) + violationsClose
	if got := sandboxDenials(text); len(got) != maxDenials {
		t.Errorf("%d denials, want the cap %d", len(got), maxDenials)
	}
}

func denied(sid string) *hook.Payload {
	return &hook.Payload{
		HookEventName: hook.EvPostToolUseFailure, SessionID: sid, CWD: "/home/dev/src/myrepo", PermissionMode: "default",
		ToolName: "Bash", ToolUseID: "t1", ToolInput: map[string]any{"command": "curl -sS https://example.com"},
		Error: observedDenial,
	}
}

func TestDeniedToolCallSendsASandboxDenialEvent(t *testing.T) {
	c, events, traj := newTestCollector(t)
	c.Handle(denied("s1"))

	got := siemLines(t, events, event.KindSandboxDenial)
	if len(got) != 1 {
		t.Fatalf("sandbox_denial events = %d, want 1", len(got))
	}
	m := got[0]
	if m["tool_use_id"] != "t1" || m["tool_name"] != "Bash" || m["session_id"] != "s1" {
		t.Errorf("sandbox_denial = %v, want Bash t1 in s1", m)
	}
	ops, _ := m["sandbox_denial_ops"].([]any)
	digests, _ := m["sandbox_denial_digests"].([]any)
	if len(ops) != 1 || ops[0] != "network-outbound" || len(digests) != 1 {
		t.Errorf("ops = %v, digests = %v, want one network-outbound with one digest", ops, digests)
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "example.com") {
		t.Errorf("the denied host crossed in cleartext: %s", raw)
	}
	for _, absent := range []string{"bash_command_class", "path_zone", "secret_hit_kinds"} {
		if _, ok := m[absent]; ok {
			t.Errorf("sandbox_denial carries %s, so a tool rule could match it", absent)
		}
	}
	if traj.count() != 1 {
		t.Errorf("spool got %d events, want 1: the denial is SIEM-only, rebuildable from the tool_fail", traj.count())
	}
}

func TestOrdinaryFailureSendsNoSandboxDenial(t *testing.T) {
	c, events, _ := newTestCollector(t)
	p := denied("s1")
	p.Error = "Exit code 1\nmake: *** [test] Error 1"
	c.Handle(p)
	if got := siemLines(t, events, event.KindSandboxDenial); len(got) != 0 {
		t.Errorf("a failure with no violations block sent %d sandbox_denial events", len(got))
	}
}

// A command's output reaches the parser, so a forged block must not get anything but a cleaned op
// through, nor more than maxDenials of them.
func FuzzSandboxDenialsStayClean(f *testing.F) {
	f.Add(observedDenial)
	f.Add("<sandbox_violations>\ndeny \x00\xff x (y)\ndeny NETWORK h:1\n</sandbox_violations>")
	f.Add("<sandbox_violations>deny a b (c)")
	f.Fuzz(func(t *testing.T, text string) {
		ds := sandboxDenials(text)
		if len(ds) > maxDenials {
			t.Fatalf("%d denials, cap is %d", len(ds), maxDenials)
		}
		for _, d := range ds {
			if d.op != "other" {
				if d.op == "" || len(d.op) > maxOpLen || strings.Trim(d.op, "abcdefghijklmnopqrstuvwxyz-") != "" {
					t.Fatalf("op %q is not clean", d.op)
				}
			}
		}
	})
}
