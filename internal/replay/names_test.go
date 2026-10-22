package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The corpus was written with key names this project guessed for the hook payload. Claude Code
// sends different ones for three of them (internal/hook/testdata/claude-code-2.1.278-shapes.txt).
// The corpus is kept as written, and this test replays a copy with the real names: every verdict
// and every field the replay records must come out the same, so detection does not depend on
// which spelling a payload uses.
var realNames = strings.NewReplacer(
	`"user_input":`, `"prompt":`,
	`"tool_result":`, `"tool_response":`,
	`"tool_error":`, `"error":`,
)

func TestCorpusReplaysIdenticallyWithClaudeCodesRealKeyNames(t *testing.T) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	renamed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(corpusDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		rewritten := realNames.Replace(text)
		if rewritten != text {
			renamed++
		}
		if err := os.WriteFile(filepath.Join(out, e.Name()), []byte(rewritten), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if renamed < 10 {
		t.Fatalf("only %d corpus files use a legacy key name; the rewrite is not exercising the corpus", renamed)
	}

	orig, err := Load(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	real, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(orig) != len(real) {
		t.Fatalf("loaded %d scenarios, then %d after the rewrite", len(orig), len(real))
	}

	for i := range orig {
		a := Run(orig[i], Options{Config: DefaultConfig()})
		b := Run(real[i], Options{Config: DefaultConfig()})
		if b.Failed() {
			t.Errorf("%s: fails with the real key names: %+v", orig[i].Name, b.Steps)
		}
		ja, _ := json.Marshal(a.Steps)
		jb, _ := json.Marshal(b.Steps)
		if string(ja) != string(jb) {
			t.Errorf("%s: replay results differ when the payload uses Claude Code's key names\n  legacy: %s\n  real:   %s", orig[i].Name, ja, jb)
		}
	}
}
