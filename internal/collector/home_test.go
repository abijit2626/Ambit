package collector

import (
	"io"
	"log/slog"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/hook"
)

// systemCollector is ambitd as a system service: no home in the configuration, so the
// detected one is the service account's (root here), not the developer's.
func systemCollector(t *testing.T) (*Collector, *memSink) {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HomeIsDetected() {
		t.Fatal("test premise broken: a config with no home should report a detected one")
	}
	if cfg.Home == "/home/dev" {
		t.Skip("the test account's home is /home/dev, so the cases below cannot tell the homes apart")
	}
	cfg.SampleRate = 0
	traj := &memSink{}
	c := New(Options{
		Config:         cfg,
		EventsSink:     &memSink{},
		TrajectorySink: traj,
		Extractor:      features.New([]byte("test-key-that-is-long-enough-abcdef")),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:        "test",
	})
	return c, traj
}

func readAt(sid, transcript, file string) *hook.Payload {
	return &hook.Payload{
		HookEventName: hook.EvPreToolUse, SessionID: sid, CWD: "/home/dev/src/r",
		TranscriptPath: transcript, ToolName: "Read", ToolInput: map[string]any{"file_path": file},
	}
}

func zoneOf(t *testing.T, traj *memSink) string {
	t.Helper()
	e := last(t, traj)
	if e.Tool == nil || len(e.Tool.Paths) == 0 {
		t.Fatalf("event has no path: %+v", e.Tool)
	}
	return e.Tool.Paths[0].Zone
}

const devTranscript = "/home/dev/.claude/projects/-home-dev-src-r/s1.jsonl"

// Run as root, ambitd's own home is /root. A developer's file outside the working
// directory is still in that developer's home, and must be classified so.
func TestASystemServiceClassifiesAgainstTheSessionsOwnHome(t *testing.T) {
	c, traj := systemCollector(t)

	c.Handle(readAt("s1", devTranscript, "/home/dev/notes/todo.txt"))
	if got := zoneOf(t, traj); got != event.ZoneHome {
		t.Errorf("zone = %q, want %q: the session's home comes from its transcript path", got, event.ZoneHome)
	}

	// Premise: without the transcript path the same read loses its home zone, which is
	// the bug a system service would otherwise have.
	c.Handle(readAt("s2", "", "/home/dev/notes/todo.txt"))
	if got := zoneOf(t, traj); got == event.ZoneHome {
		t.Errorf("test premise broken: with no transcript path the read is still %q", got)
	}
}

// Claude Code may send the transcript path only on a later event. The zoner must pick it
// up then rather than keep the service account's home for the rest of the session.
func TestALaterTranscriptPathCorrectsTheSessionsHome(t *testing.T) {
	c, traj := systemCollector(t)
	c.Handle(readAt("s1", "", "/home/dev/notes/todo.txt"))
	c.Handle(readAt("s1", devTranscript, "/home/dev/notes/todo.txt"))
	if got := zoneOf(t, traj); got != event.ZoneHome {
		t.Errorf("zone = %q after the transcript path arrived, want %q", got, event.ZoneHome)
	}
}

// A home the configuration sets is a decision, and a payload does not override it.
func TestAConfiguredHomeIsNotOverriddenByTheTranscript(t *testing.T) {
	c, _, traj := newTestCollector(t) // Home: /home/dev, set explicitly
	if c.cfg.HomeIsDetected() {
		t.Fatal("test premise broken: newTestCollector's home should count as configured")
	}
	c.Handle(readAt("s1", "/home/mallory/.claude/projects/x/s1.jsonl", "/home/dev/notes/todo.txt"))
	if got := zoneOf(t, traj); got != event.ZoneHome {
		t.Errorf("zone = %q, want %q: the configured home must win over the payload's", got, event.ZoneHome)
	}
}

func TestHomeFromTranscript(t *testing.T) {
	cases := map[string]string{
		"/home/dev/.claude/projects/-home-dev-src-r/s.jsonl":      "/home/dev",
		"/Users/dev/.claude/projects/x/s.jsonl":                   "/Users/dev",
		`C:\Users\dev\.claude\projects\C--src-r\s.jsonl`:          "C:/Users/dev",
		"/opt/claude-config/projects/x/s.jsonl":                   "", // CLAUDE_CONFIG_DIR elsewhere
		"/.claude/projects/x/s.jsonl":                             "", // no home before it
		"":                                                        "",
		"/home/dev/src/r/.claude/settings.json":                   "",
		"/home/dev/.claude/projects/a/.claude/projects/b/s.jsonl": "/home/dev",
	}
	for in, want := range cases {
		if got := homeFromTranscript(in); got != want {
			t.Errorf("homeFromTranscript(%q) = %q, want %q", in, got, want)
		}
	}
}
