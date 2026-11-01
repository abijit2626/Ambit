package doctor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/config"
)

func privateLayout(t *testing.T) config.Config {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("modes are not checked on Windows")
	}
	data := filepath.Join(t.TempDir(), "ambit")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.TrajectoryPath = filepath.Join(data, "trajectory.jsonl")
	cfg.EventsPath = filepath.Join(data, "events.jsonl")
	cfg.FingerprintKeyPath = filepath.Join(data, "fingerprint.key")
	cfg.BaselineDir = filepath.Join(data, "baselines")
	for p, body := range map[string]string{
		cfg.TrajectoryPath:     "{}\n",
		cfg.EventsPath:         "{}\n",
		cfg.FingerprintKeyPath: strings.Repeat("k", 32),
		cfg.EgressProfile():    "hmac:a\n",
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(cfg.BaselineDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPrivateFilesPass(t *testing.T) {
	got := filesFinding(privateLayout(t))
	if len(got) != 1 || got[0].Level != OK || !strings.Contains(got[0].Detail, "6 of ambitd's files") {
		t.Fatalf("findings = %+v", got)
	}
}

func TestOpenFilesFail(t *testing.T) {
	cfg := privateLayout(t)
	for p, mode := range map[string]os.FileMode{
		cfg.FingerprintKeyPath: 0o644,
		cfg.EventsPath:         0o640,
		cfg.BaselineDir:        0o755,
	} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	got := filesFinding(cfg)
	want := map[string]string{
		"fingerprint key":    "its group and everyone",
		"events sink":        "open to its group; ambitd creates it 0600",
		"baseline directory": "ambitd creates it 0700",
	}
	for what, detail := range want {
		found := false
		for _, f := range got {
			if f.Level == Fail && strings.Contains(f.Detail, what) && strings.Contains(f.Detail, detail) {
				found = true
			}
		}
		if !found {
			t.Errorf("no failure for the %s containing %q in %+v", what, detail, got)
		}
	}
	for _, f := range got {
		if strings.Contains(f.Detail, "spool") || strings.Contains(f.Detail, "egress profile") {
			t.Errorf("a private file was reported: %+v", f)
		}
	}
}

func TestShortKeyFails(t *testing.T) {
	cfg := privateLayout(t)
	if err := os.WriteFile(cfg.FingerprintKeyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filesFinding(cfg)
	if len(got) != 1 || got[0].Level != Fail || !strings.Contains(got[0].Detail, "refuses to start") {
		t.Fatalf("findings = %+v", got)
	}
}

func TestMissingFilesAreNotFindings(t *testing.T) {
	cfg := privateLayout(t)
	if err := os.Remove(cfg.EgressProfile()); err != nil {
		t.Fatal(err)
	}
	got := filesFinding(cfg)
	if len(got) != 1 || got[0].Level != OK || !strings.Contains(got[0].Detail, "5 of") {
		t.Fatalf("a file ambitd has not created yet must not be a finding: %+v", got)
	}
}

func TestUninspectableFilesWarnOnce(t *testing.T) {
	cfg := privateLayout(t)
	if os.Geteuid() == 0 {
		t.Skip("root can stat anything")
	}
	dir := filepath.Dir(cfg.TrajectoryPath)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	got := filesFinding(cfg)
	warns := 0
	for _, f := range got {
		if f.Level == Warn {
			warns++
		}
	}
	if warns != 1 {
		t.Errorf("want one warning naming what could not be inspected: %+v", got)
	}
}
