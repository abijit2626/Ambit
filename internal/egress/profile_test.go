package egress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digest(s string) string { return "hmac:" + s }

func TestNewDestinationIsReportedOnceAndRemembered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.txt")
	p, err := Load(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsNew(digest("a")) {
		t.Fatal("an empty profile must report a destination as new")
	}
	if err := p.Record(digest("a")); err != nil {
		t.Fatal(err)
	}
	if p.IsNew(digest("a")) {
		t.Error("a recorded destination must not be reported again")
	}
	if err := p.Record(digest("a")); err != nil {
		t.Fatal(err)
	}
	if got := p.Size(); got != 1 {
		t.Errorf("size = %d after recording one destination twice, want 1", got)
	}
}

func TestIsNewChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.txt")
	p, _ := Load(path, 0)
	for i := 0; i < 3; i++ {
		if !p.IsNew(digest("a")) {
			t.Fatal("IsNew must keep reporting a destination until it is recorded")
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("IsNew wrote the profile: %v", err)
	}
}

func TestProfileSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.txt")
	p, _ := Load(path, 0)
	for _, d := range []string{digest("a"), digest("b")} {
		if err := p.Record(d); err != nil {
			t.Fatal(err)
		}
	}
	q, err := Load(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if q.IsNew(digest("a")) || q.IsNew(digest("b")) {
		t.Error("destinations recorded before a restart are reported as new after it")
	}
	if !q.IsNew(digest("c")) {
		t.Error("a destination never recorded must still be new")
	}
}

func TestFullProfileStopsLearningAndCountsOverflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.txt")
	p, _ := Load(path, 2)
	for _, d := range []string{digest("a"), digest("b")} {
		if err := p.Record(d); err != nil {
			t.Fatal(err)
		}
	}
	if p.IsNew(digest("c")) {
		t.Error("a full profile must not report a new destination, or every contact would be reported")
	}
	if err := p.Record(digest("c")); err != nil {
		t.Fatal(err)
	}
	if got := p.Overflow(); got != 2 {
		t.Errorf("overflow = %d, want 2 (the IsNew and the Record both refused c)", got)
	}
	q, _ := Load(path, 2)
	if q.Size() != 2 {
		t.Errorf("the file holds %d destinations after overflow, want 2", q.Size())
	}
}

func TestDamagedProfileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.txt")
	if err := os.WriteFile(path, []byte("hmac:a\nexample.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, 0); err == nil || !strings.Contains(err.Error(), "not a digest") {
		t.Fatalf("Load = %v, want an error naming the bad line", err)
	}
}

func TestEmptyPathIsAnError(t *testing.T) {
	if _, err := Load("", 0); err == nil {
		t.Fatal("an empty path must be an error")
	}
}
