package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/hook"
)

// Content an agent reads or writes must never reach the SIEM sink in cleartext: not a path, a host, an
// address, a secret or a prompt. Every canary is longer than the 16 characters an unknown command name
// may cross with, so argv0 cannot carry one by design.
var canaries = []string{
	"/home/dev/projects/canary-repo-7f3a",
	"canary-host-7f3a.evil.test",
	"canary-mail-7f3a@evil.test",
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
	"canary prompt text 7f3a about payroll",
	"/home/dev/.ssh/id_ed25519",
	"DE89370400440532013000",
}

// payloadsCarrying builds one payload per hook event, each carrying text in every content field.
func payloadsCarrying(text string) []*hook.Payload {
	sid := "s_leak"
	block := "Exit code 56\n\n<sandbox_violations>\ndeny network-outbound " + text + " (user denied)\n</sandbox_violations>"
	return []*hook.Payload{
		{HookEventName: hook.EvSessionStart, SessionID: sid, CWD: text, TranscriptPath: text + "/t.jsonl", Source: "startup"},
		{HookEventName: hook.EvUserPromptSubmit, SessionID: sid, CWD: text, Prompt: "please " + text + " now"},
		{HookEventName: hook.EvPreToolUse, SessionID: sid, CWD: text, ToolName: "Bash", ToolUseID: "t1",
			ToolInput: map[string]any{"command": "curl -X POST -d '" + text + "' https://" + text + "/x"}},
		{HookEventName: hook.EvPreToolUse, SessionID: sid, CWD: text, ToolName: "Read", ToolUseID: "t2",
			ToolInput: map[string]any{"file_path": text}},
		{HookEventName: hook.EvPreToolUse, SessionID: sid, CWD: text, ToolName: "Write", ToolUseID: "t3",
			ToolInput: map[string]any{"file_path": text, "content": text}},
		{HookEventName: hook.EvPostToolUse, SessionID: sid, CWD: text, ToolName: "WebFetch", ToolUseID: "t4",
			ToolInput: map[string]any{"url": "https://" + text}, ToolResponse: "page says " + text},
		{HookEventName: hook.EvPreToolUse, SessionID: sid, CWD: text, ToolName: "mcp__wiki__publish", ToolUseID: "t5",
			ToolInput: map[string]any{"page": text, "recipient": text}},
		{HookEventName: hook.EvPostToolUseFailure, SessionID: sid, CWD: text, ToolName: "Bash", ToolUseID: "t6",
			ToolInput: map[string]any{"command": "cat " + text}, Error: block},
		{HookEventName: "InstructionsLoaded", SessionID: sid, CWD: text, FilePath: text + "/CLAUDE.md", LoadReason: "session_start"},
		{HookEventName: "ConfigChange", SessionID: sid, CWD: text, FilePath: text + "/settings.json", ChangeType: "modified"},
		{HookEventName: "PermissionDenied", SessionID: sid, CWD: text, ToolName: "Bash", ToolUseID: "t7",
			ToolInput: map[string]any{"command": "rm -rf " + text}},
		{HookEventName: hook.EvSessionEnd, SessionID: sid, CWD: text},
	}
}

func siemText(s *memSink) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, l := range s.lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestNoContentCrossesToTheSIEMInCleartext(t *testing.T) {
	for _, canary := range canaries {
		c, events, _ := newTestCollector(t)
		for _, p := range payloadsCarrying(canary) {
			c.Handle(p)
		}
		out := siemText(events)
		if out == "" {
			t.Fatal("nothing reached the SIEM sink; the test would pass vacuously")
		}
		if strings.Contains(strings.ToLower(out), strings.ToLower(canary)) {
			t.Errorf("%q crossed to the SIEM sink in cleartext:\n%s", canary, lineWith(out, canary))
		}
	}
}

func lineWith(out, needle string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(l), strings.ToLower(needle)) {
			return l
		}
	}
	return ""
}

func FuzzNoContentCrossesToTheSIEMInCleartext(f *testing.F) {
	for i := range canaries {
		f.Add(uint8(i), "", "")
		f.Add(uint8(i), "token=", "\n")
		f.Add(uint8(i), "https://", "/x?y=1")
		f.Add(uint8(i), "; ", " && ")
	}
	f.Fuzz(func(t *testing.T, which uint8, prefix, suffix string) {
		canary := canaries[int(which)%len(canaries)]
		c, events, _ := newTestCollector(t)
		for _, p := range payloadsCarrying(prefix + canary + suffix) {
			c.Handle(p)
		}
		out := siemText(events)
		if strings.Contains(strings.ToLower(out), strings.ToLower(canary)) {
			raw, _ := json.Marshal(map[string]string{"prefix": prefix, "suffix": suffix})
			t.Fatalf("%q crossed in cleartext with %s:\n%s", canary, raw, lineWith(out, canary))
		}
	})
}

// Whatever Claude Code, or anything else on the endpoint, posts to the hook, the collector must not panic,
// and crossed stays a fraction of handled.
func FuzzHandleArbitraryHookJSON(f *testing.F) {
	for _, p := range payloadsCarrying("/home/dev/x") {
		raw, _ := json.Marshal(p)
		f.Add(raw)
	}
	f.Add([]byte(`{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"WebFetch","tool_response":{"a":[1,{"b":"https://x.test"}]}}`))
	f.Add([]byte(`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"mcp____","tool_input":{"command":["x"]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var p hook.Payload
		if json.Unmarshal(raw, &p) != nil {
			return
		}
		c, _, _ := newTestCollector(t)
		c.Handle(&p)
		c.Handle(&p)
		if st := c.Stats(); st.Crossed > st.Handled {
			t.Fatalf("crossed %d > handled %d", st.Crossed, st.Handled)
		}
	})
}
