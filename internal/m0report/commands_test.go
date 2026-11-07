package m0report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func toolLine(kind, argv0, class string) string {
	return fmt.Sprintf(`{"ts":"2026-11-01T10:00:00Z","source":"hook","kind":%q,"session":{"session_id":"s1"},"tool":{"name":"Bash","bash":{"argv0":%q,"command_class":%q}}}`, kind, argv0, class)
}

func TestCommandsAreCountedByClassWithTheCommonestOthers(t *testing.T) {
	var lines []string
	add := func(n int, kind, argv0, class string) {
		for i := 0; i < n; i++ {
			lines = append(lines, toolLine(kind, argv0, class))
		}
	}
	add(5, "tool_pre", "curl", "network")
	add(3, "tool_pre", "ls", "read_only")
	add(4, "tool_pre", "mytool", "other")
	add(2, "tool_pre", "", "other")
	add(1, "tool_pre", "fancy-runner", "other")
	add(9, "tool_post", "curl", "network") // a PostToolUse of the same calls is not counted again
	lines = append(lines, `{"ts":"2026-11-01T10:00:00Z","source":"hook","kind":"tool_pre","session":{"session_id":"s1"},"tool":{"name":"Read"}}`)

	p := filepath.Join(t.TempDir(), "trajectory.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Build([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	c := r.Commands
	if c.Total != 15 || c.ByClass["network"] != 5 || c.ByClass["read_only"] != 3 || c.ByClass["other"] != 7 {
		t.Fatalf("commands = %d %v, want 15: network 5, read_only 3, other 7", c.Total, c.ByClass)
	}
	want := []NameCount{{"mytool", 4}, {"(unnamed)", 2}, {"fancy-runner", 1}}
	if fmt.Sprint(c.TopOther) != fmt.Sprint(want) {
		t.Errorf("top other = %v, want %v", c.TopOther, want)
	}
	var buf bytes.Buffer
	r.WriteText(&buf, false)
	for _, s := range []string{"15 commands: network 5, other 7, read_only 3", "most often classed other: mytool 4, (unnamed) 2, fancy-runner 1"} {
		if !strings.Contains(buf.String(), s) {
			t.Errorf("report lacks %q:\n%s", s, buf.String())
		}
	}
}

func TestTopOtherIsBounded(t *testing.T) {
	var c Commands
	for i := 0; i < 30; i++ {
		c.add("other", fmt.Sprintf("tool%02d", i))
	}
	c.finish()
	if len(c.TopOther) != topOther {
		t.Errorf("%d names, want %d", len(c.TopOther), topOther)
	}
}
