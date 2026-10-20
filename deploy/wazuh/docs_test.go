package wazuh

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func markdownFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "answer-key", "analyst":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".md") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no markdown files found")
	}
	return out
}

func TestDocsDoNotTellAnOperatorToUseQuietLogtest(t *testing.T) {
	for _, path := range markdownFiles(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		inFence := false
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inFence = !inFence
				continue
			}
			if inFence && strings.Contains(line, "wazuh-logtest") && regexp.MustCompile(`wazuh-logtest\s+(-\w+\s+)*-q\b`).MatchString(line) {
				t.Errorf("%s:%d runs wazuh-logtest -q: on Wazuh 4.14.8 that prints nothing for a line that matches, so the loop reads as a quiet fleet; run it without -q and with 2>&1 because the result goes to stderr", path, i+1)
			}
		}
	}
}

func TestDocsDoNotTellAnOperatorToLookForSessionStart(t *testing.T) {
	instruction := regexp.MustCompile("(?i)(check|confirm|verify|look for)[^\\n]*session_start")
	for _, path := range markdownFiles(t) {
		if strings.Contains(path, "runbooks") || strings.HasSuffix(path, "03-detection.md") || strings.HasSuffix(path, "04-data-model.md") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if instruction.MatchString(line) && strings.Contains(line, "events.jsonl") {
				t.Errorf("%s:%d tells the operator to look for a session_start line in events.jsonl, but SessionStart never reached ambitd in the lab; name an event that does arrive (prompt_submit)", path, i+1)
			}
		}
	}
}
