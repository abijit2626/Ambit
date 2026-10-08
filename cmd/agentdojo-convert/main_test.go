package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abijit2626/ambit/internal/replay"
)

const fixtures = "../../internal/agentdojo/testdata/runs"

func invoke(t *testing.T, args ...string) int {
	t.Helper()
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = append([]string{"agentdojo-convert"}, args...)
	return run()
}

func TestConvertsTheFixturesIntoAReplayableCorpus(t *testing.T) {
	out := filepath.Join(t.TempDir(), "conv")
	if got := invoke(t, "-out", out, fixtures); got != 0 {
		t.Fatalf("exit = %d", got)
	}
	scs, err := replay.Load(out)
	if err != nil {
		t.Fatalf("the output is not a replay corpus: %v", err)
	}
	if len(scs) != 6 {
		t.Errorf("scenarios = %d, want 6 (one per fixture)", len(scs))
	}
}

func TestRefusesADirectoryThatAlreadyHoldsTrajectories(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "old.jsonl"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := invoke(t, "-out", out, fixtures); got != 1 {
		t.Errorf("exit = %d, want 1: mixing two conversions replays a corpus that is neither", got)
	}
}

func TestAMalformedRunLogIsAnErrorNotASkip(t *testing.T) {
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "bad.json"), []byte(`{"not":"a run"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := invoke(t, "-out", filepath.Join(t.TempDir(), "o"), in); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

func TestTwoCopiesOfOneRunAreRefused(t *testing.T) {
	src := filepath.Join(fixtures, "claude-3-7-sonnet-20250219/slack/user_task_0/none/none.json")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	in := t.TempDir()
	for _, d := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(in, d), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(in, d, "none.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := invoke(t, "-out", filepath.Join(t.TempDir(), "o"), in); got != 1 {
		t.Errorf("exit = %d, want 1: one scenario name for two files would silently overwrite", got)
	}
}

func TestUsageErrors(t *testing.T) {
	if got := invoke(t, fixtures); got != 1 {
		t.Errorf("no -out: exit = %d, want 1", got)
	}
	if got := invoke(t, "-out", t.TempDir()); got != 1 {
		t.Errorf("no input: exit = %d, want 1", got)
	}
	if got := invoke(t, "-out", filepath.Join(t.TempDir(), "o"), t.TempDir()); got != 1 {
		t.Errorf("no run logs: exit = %d, want 1", got)
	}
}
