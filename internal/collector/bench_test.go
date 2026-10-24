package collector

import (
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/hook"
)

func benchPayloads() []*hook.Payload {
	page := strings.Repeat("Setup notes for the billing service. See https://docs.example.com/billing and mail ops@example.com. ", 40)
	return []*hook.Payload{
		{HookEventName: hook.EvUserPromptSubmit, SessionID: "s_bench", PermissionMode: "default", CWD: "/home/dev/src/myrepo", Prompt: "fix the failing billing test"},
		{HookEventName: hook.EvPreToolUse, SessionID: "s_bench", PermissionMode: "default", CWD: "/home/dev/src/myrepo", ToolName: "Read", ToolUseID: "t1",
			ToolInput: map[string]any{"file_path": "/home/dev/src/myrepo/billing.go"}},
		{HookEventName: hook.EvPostToolUse, SessionID: "s_bench", PermissionMode: "default", CWD: "/home/dev/src/myrepo", ToolName: "WebFetch", ToolUseID: "t2",
			ToolInput: map[string]any{"url": "https://docs.example.com/billing"}, ToolResponse: page},
		{HookEventName: hook.EvPreToolUse, SessionID: "s_bench", PermissionMode: "default", CWD: "/home/dev/src/myrepo", ToolName: "Bash", ToolUseID: "t3",
			ToolInput: map[string]any{"command": "go test ./... && curl -sS https://docs.example.com/billing"}},
	}
}

// BenchmarkHandle measures the work a hook call does inside ambitd for a typical mix of events. The hook
// response waits on it, against a 5 ms budget.
func BenchmarkHandle(b *testing.B) {
	ps := benchPayloads()
	c, _, _ := newTestCollector(b)
	c.events, c.traj = discard{}, discard{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Handle(ps[i%len(ps)])
	}
}

type discard struct{}

func (discard) Write(any) bool { return true }

func BenchmarkHandleByKind(b *testing.B) {
	names := []string{"prompt", "read", "webfetch_4k", "bash"}
	for i, p := range benchPayloads() {
		b.Run(names[i], func(b *testing.B) {
			c, _, _ := newTestCollector(b)
			c.events, c.traj = discard{}, discard{}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				c.Handle(p)
			}
		})
	}
}
