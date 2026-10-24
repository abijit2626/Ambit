package collector

import (
	"testing"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/hook"
)

func start(sid, source string) *hook.Payload {
	return &hook.Payload{HookEventName: hook.EvSessionStart, SessionID: sid, Source: source, CWD: "/home/dev/src/myrepo"}
}

func readCall(sid, mode, id string) *hook.Payload {
	return &hook.Payload{
		HookEventName: hook.EvPreToolUse, SessionID: sid, PermissionMode: mode, CWD: "/home/dev/src/myrepo",
		ToolName: "Read", ToolUseID: id, ToolInput: map[string]any{"file_path": "/home/dev/src/myrepo/a.go"},
	}
}

func noPrompts(t *testing.T, s *memSink) []map[string]any {
	t.Helper()
	return siemLines(t, s, event.KindSessionNoPrompt)
}

func TestToolCallBeforeAnyPromptIsReportedOnce(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(start("s1", "startup"))
	c.Handle(readCall("s1", "bypassPermissions", "t1"))
	c.Handle(readCall("s1", "bypassPermissions", "t2"))

	got := noPrompts(t, events)
	if len(got) != 1 {
		t.Fatalf("session_no_prompt events = %d, want 1: the first tool call only", len(got))
	}
	m := got[0]
	if m["session_id"] != "s1" || m["tool_use_id"] != "t1" || m["tool_name"] != "Read" || m["permission_mode"] != "bypassPermissions" {
		t.Errorf("session_no_prompt = %v, want s1, t1, Read, bypassPermissions", m)
	}
	for _, absent := range []string{"path_zone", "bash_command_class", "policy_decision", "secret_hit_kinds"} {
		if _, ok := m[absent]; ok {
			t.Errorf("session_no_prompt carries %s, so a tool rule could match it", absent)
		}
	}
}

func TestPromptedSessionIsNotReported(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(start("s1", "startup"))
	c.Handle(modePrompt("s1", "default"))
	for i := 0; i < 50; i++ {
		c.Handle(readCall("s1", "default", "t"))
	}
	if got := noPrompts(t, events); len(got) != 0 {
		t.Errorf("a prompted session was reported: %v. A long autonomous run after one prompt is normal", got)
	}
}

func TestSessionAmbitdDidNotSeeStartIsNotReported(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(readCall("s1", "default", "t1"))
	if got := noPrompts(t, events); len(got) != 0 {
		t.Errorf("reported a session whose start ambitd never saw: %v. It may have begun before ambitd did", got)
	}
}

func TestCompactionDoesNotRestartTheSession(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(start("s1", "startup"))
	c.Handle(modePrompt("s1", "default"))
	c.Handle(start("s1", "compact"))
	c.Handle(readCall("s1", "default", "t1"))
	if got := noPrompts(t, events); len(got) != 0 {
		t.Errorf("tool calls after compaction were reported as prompt-less: %v", got)
	}
}

func TestResumeOrClearStartsTheCheckAgain(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(start("s1", "startup"))
	c.Handle(modePrompt("s1", "default"))
	c.Handle(start("s1", "resume"))
	c.Handle(readCall("s1", "default", "t1"))
	if got := noPrompts(t, events); len(got) != 1 {
		t.Errorf("session_no_prompt events = %d, want 1: a resumed session that acts before a prompt is reported", len(got))
	}
}

func TestRefusedNoPromptIsSentWithTheNextToolCall(t *testing.T) {
	events := &refusable{memSink: &memSink{}}
	c := newCollectorWithEventsSink(t, events)
	c.Handle(start("s1", "startup"))
	events.refuse = true
	c.Handle(readCall("s1", "default", "t1"))
	events.refuse = false
	c.Handle(readCall("s1", "default", "t2"))
	c.Handle(readCall("s1", "default", "t3"))

	got := noPrompts(t, events.memSink)
	if len(got) != 1 || got[0]["tool_use_id"] != "t2" {
		t.Errorf("session_no_prompt events = %v, want one, for t2: the refused report retried with the next call", got)
	}
}
