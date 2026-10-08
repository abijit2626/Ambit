package main

import (
	"os"
	"path/filepath"
	"testing"
)

const corpus = "../../testdata/replay"

// invoke runs the command with the given arguments and returns its exit status.
func invoke(t *testing.T, args ...string) int {
	t.Helper()
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = append([]string{"ambit-replay"}, args...)
	return run()
}

func TestExitStatuses(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"the corpus passes", []string{corpus}, 0},
		{"json output", []string{"-json", corpus}, 0},
		{"a gate the corpus meets", []string{"-min-recall", "0.1", "-max-fpr", "0.9", corpus}, 0},
		{"a recall gate it misses", []string{"-min-recall", "0.99", corpus}, 2},
		{"a false-positive gate it misses", []string{"-max-fpr", "0.01", corpus}, 2},
		{"no arguments", nil, 1},
		{"a missing scenario path", []string{missing}, 1},
		{"a missing explicit config", []string{"-config", missing, corpus}, 1},
		{"an unknown flag", []string{"-nonsense", corpus}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := invoke(t, c.args...); got != c.want {
				t.Errorf("exit = %d, want %d", got, c.want)
			}
		})
	}
}

// A failing assertion must fail the run, or the corpus is decoration.
func TestAFailingAssertionExitsTwo(t *testing.T) {
	d := t.TempDir()
	body := `{"payload":{"hook_event_name":"PreToolUse","session_id":"s","cwd":"/home/dev/r","tool_name":"Read","tool_input":{"file_path":"/home/dev/r/a.go"}},"expect":{"edge":true}}` + "\n"
	if err := os.WriteFile(filepath.Join(d, "bad.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := invoke(t, d); got != 2 {
		t.Errorf("exit = %d, want 2", got)
	}
}

// A gate on a metric the corpus cannot compute must fail, not pass.
func TestAGateOnAnUndefinedMetricExitsTwo(t *testing.T) {
	d := t.TempDir()
	body := `{"hook_event_name":"SessionStart","session_id":"s"}` + "\n"
	if err := os.WriteFile(filepath.Join(d, "bare.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := invoke(t, "-min-recall", "0.5", d); got != 2 {
		t.Errorf("exit = %d, want 2: a corpus with no ground truth measured nothing", got)
	}
}
