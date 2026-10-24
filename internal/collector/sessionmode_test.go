package collector

import (
	"testing"

	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/hook"
)

func modePrompt(sid, mode string) *hook.Payload {
	return &hook.Payload{HookEventName: hook.EvUserPromptSubmit, SessionID: sid, PermissionMode: mode, Prompt: "fix the test"}
}

func modeLines(t *testing.T, s *memSink) []string {
	t.Helper()
	var modes []string
	for _, m := range siemLines(t, s, event.KindSessionMode) {
		mode, _ := m["permission_mode"].(string)
		modes = append(modes, mode)
	}
	return modes
}

func TestSessionModeIsSentWhenTheModeIsFirstKnownNotAtSessionStart(t *testing.T) {
	c, events, _ := newTestCollector(t)

	c.Handle(&hook.Payload{HookEventName: hook.EvSessionStart, SessionID: "s1"})
	if got := modeLines(t, events); len(got) != 0 {
		t.Fatalf("session_mode sent at a SessionStart that carries no mode: %v", got)
	}

	c.Handle(modePrompt("s1", "bypassPermissions"))
	c.Handle(modePrompt("s1", "bypassPermissions"))
	got := modeLines(t, events)
	if len(got) != 1 || got[0] != "bypassPermissions" {
		t.Fatalf("session_mode events = %v, want one bypassPermissions: the first prompt carries the mode", got)
	}

	m := siemLines(t, events, event.KindSessionMode)[0]
	if m["session_id"] != "s1" || m["src"] != string(event.SourceAmbitd) {
		t.Errorf("session_mode = %v, want session s1 from ambitd", m)
	}
	for _, absent := range []string{"tool_name", "path_zone", "policy_decision"} {
		if _, ok := m[absent]; ok {
			t.Errorf("session_mode carries %s, so a tool rule could match it", absent)
		}
	}
}

func TestSessionModeIsSentAgainOnEachChange(t *testing.T) {
	c, events, _ := newTestCollector(t)

	c.Handle(modePrompt("s1", "default"))
	c.Handle(modePrompt("s1", "default"))
	c.Handle(modePrompt("s1", "bypassPermissions"))
	c.Handle(modePrompt("s1", "default"))

	got := modeLines(t, events)
	want := []string{"default", "bypassPermissions", "default"}
	if len(got) != len(want) {
		t.Fatalf("session_mode events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("session_mode[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestSessionModeIsPerSession(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(modePrompt("s1", "bypassPermissions"))
	c.Handle(modePrompt("s2", "bypassPermissions"))
	if got := modeLines(t, events); len(got) != 2 {
		t.Errorf("session_mode events = %v, want one per session", got)
	}
}

func TestRefusedSessionModeIsSentWithTheNextEvent(t *testing.T) {
	events := &refusable{memSink: &memSink{}, refuse: true}
	c := newCollectorWithEventsSink(t, events)

	c.Handle(modePrompt("s1", "bypassPermissions"))
	events.refuse = false
	c.Handle(modePrompt("s1", "bypassPermissions"))
	c.Handle(modePrompt("s1", "bypassPermissions"))

	if got := modeLines(t, events.memSink); len(got) != 1 {
		t.Errorf("session_mode events = %v, want exactly one: the refused send retried once", got)
	}
}

func TestSessionModeSurvivesARefusalAfterALaterChange(t *testing.T) {
	c, _, _ := newTestCollector(t)
	c.Handle(modePrompt("s1", "default"))
	st := c.sessions["s1"]

	st.mu.Lock()
	st.permMode = "bypassPermissions"
	st.mu.Unlock()
	mode, prev, ok := st.takeModeChange()
	if !ok || mode != "bypassPermissions" || prev != "default" {
		t.Fatalf("takeModeChange = %q, %q, %v", mode, prev, ok)
	}
	st.unsendMode("default", "")
	if st.modeSent != "bypassPermissions" {
		t.Errorf("modeSent = %q: undoing an older send must not erase a newer one", st.modeSent)
	}
}
