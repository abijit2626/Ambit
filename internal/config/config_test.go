package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing config should not be an error: %v", err)
	}
	if cfg.HookAddr != "127.0.0.1:7777" {
		t.Errorf("HookAddr = %q, want the default", cfg.HookAddr)
	}
	if cfg.Enforce {
		t.Error("Enforce must default to false: M0 is observe-only")
	}
}

func TestLoadOverlaysOntoDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, []byte(`{"hook_addr":"127.0.0.1:9999","sample_rate":0.02}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HookAddr != "127.0.0.1:9999" || cfg.SampleRate != 0.02 {
		t.Errorf("overlay not applied: %+v", cfg)
	}
	// Absent fields keep their defaults rather than becoming zero values, which
	// would silently disable the heartbeat.
	if cfg.HealthSeconds != 60 {
		t.Errorf("HealthSeconds = %d, want the default 60", cfg.HealthSeconds)
	}
}

func TestDerivedDurations(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HealthInterval.Seconds() != 60 {
		t.Errorf("HealthInterval = %v, want 60s", cfg.HealthInterval)
	}
	if cfg.LatencyBudget.Milliseconds() != 5 {
		t.Errorf("LatencyBudget = %v, want 5ms", cfg.LatencyBudget)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		ok   bool
		why  string
	}{
		{"defaults", func(*Config) {}, true, ""},
		{"no hook addr", func(c *Config) { c.HookAddr = "" }, false, "hook_addr is required"},
		{"no events path", func(c *Config) { c.EventsPath = "" }, false, "events_path is required"},
		{"same paths", func(c *Config) { c.TrajectoryPath = c.EventsPath }, false,
			"the two sinks carry different representations with different audiences and must not collide"},
		{"negative sample rate", func(c *Config) { c.SampleRate = -0.1 }, false, "out of range"},
		{"sample rate above one", func(c *Config) { c.SampleRate = 1.5 }, false, "out of range"},
		{"sample rate one", func(c *Config) { c.SampleRate = 1 }, true, "everything crossing is valid, if unwise"},
		{"zero health seconds", func(c *Config) { c.HealthSeconds = 0 }, false,
			"the heartbeat is D7's fine half and must not be silently disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			c.mut(&cfg)
			err := cfg.Validate()
			if c.ok && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !c.ok && err == nil {
				t.Errorf("Validate() = nil, want an error (%s)", c.why)
			}
		})
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a malformed config must fail loudly rather than fall back to defaults")
	}
}

func TestTrustedMCPSet(t *testing.T) {
	cfg := Default()
	cfg.TrustedMCPServers = []string{"internal-wiki", "internal-jira"}
	set := cfg.TrustedMCPSet()
	if !set["internal-wiki"] || !set["internal-jira"] {
		t.Errorf("TrustedMCPSet = %v", set)
	}
	if set["github"] {
		t.Error("an unlisted server must not be trusted: a server never adds itself to this list")
	}
}

func TestLoadOrCreateFingerprintKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fp.key")
	generated := []byte("0123456789abcdef0123456789abcdef")

	key, err := LoadOrCreateFingerprintKey(path, func() ([]byte, error) { return generated, nil })
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != string(generated) {
		t.Error("generated key not returned")
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports 0666 or 0444 whatever was asked for; there, privacy is the
	// directory ACL, which internal/fsperm tests.
	if perm := st.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	// A second call must return the SAME key. Regenerating would break equality
	// matching against every previously stored fingerprint.
	again, err := LoadOrCreateFingerprintKey(path, func() ([]byte, error) {
		t.Error("generator called for an existing key; rotating would break all stored fingerprints")
		return nil, errors.New("must not be called")
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(generated) {
		t.Error("existing key not reused")
	}
}

func TestLoadOrCreateFingerprintKeyRejectsShortKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fp.key")
	if err := os.WriteFile(path, []byte("tooshort"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateFingerprintKey(path, nil); err == nil {
		t.Error("a short key must be rejected rather than silently weakening every digest")
	}
}
