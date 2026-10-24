package runstate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

func TestFirstRunHasNoPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	f, prev, err := Open(path, "r1", "v1", t0)
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Errorf("prev = %+v, want nil on a first run", prev)
	}
	if f.RunID() != "r1" {
		t.Errorf("run id = %q", f.RunID())
	}
}

func TestCleanStopIsReportedWithDowntimeFromTheStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	f, _, err := Open(path, "r1", "v1", t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Beat(t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := f.Stop(t0.Add(90 * time.Second)); err != nil {
		t.Fatal(err)
	}

	_, prev, err := Open(path, "r2", "v2", t0.Add(10*time.Minute+90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.Stop != StopClean || prev.RunID != "r1" || prev.Version != "v1" {
		t.Fatalf("prev = %+v, want a clean stop of r1", prev)
	}
	if prev.DownSec != 600 {
		t.Errorf("down_sec = %d, want 600", prev.DownSec)
	}
}

func TestCrashIsUncleanWithDowntimeFromTheLastHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	f, _, err := Open(path, "r1", "v1", t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Beat(t0.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}

	_, prev, err := Open(path, "r2", "v1", t0.Add(7*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.Stop != StopUnclean {
		t.Fatalf("prev = %+v, want unclean: the run never wrote a stop", prev)
	}
	if prev.DownSec != 300 {
		t.Errorf("down_sec = %d, want 300 (since the last heartbeat; an upper bound)", prev.DownSec)
	}
}

func TestUnreadableStateIsUnknownNotFirstRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, prev, err := Open(path, "r2", "v1", t0)
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.Stop != StopUnknown {
		t.Errorf("prev = %+v, want unknown: a corrupt file means a previous run existed", prev)
	}
	if err := f.Stop(t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, prev, _ = Open(path, "r3", "v1", t0.Add(2*time.Second))
	if prev == nil || prev.Stop != StopClean || prev.RunID != "r2" {
		t.Errorf("after rewrite prev = %+v, want a clean stop of r2", prev)
	}
}

func TestPathSitsBesideTheTrajectory(t *testing.T) {
	got := PathFor(filepath.Join("data", "ambit", "trajectory.jsonl"))
	if want := filepath.Join("data", "ambit", FileName); got != want {
		t.Errorf("PathFor = %q, want %q", got, want)
	}
}
