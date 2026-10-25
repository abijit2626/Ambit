package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoalDriftIsOffAndValidByDefault(t *testing.T) {
	c := Default()
	if c.GoalDrift.Enabled {
		t.Error("goal drift is on by default; it sends prompts off the endpoint and must be opted into")
	}
	c.GoalDrift.Enabled = true
	if err := c.GoalDrift.validate(); err != nil {
		t.Errorf("the defaults, switched on, do not validate: %v", err)
	}
}

func TestGoalDriftRefusesACleartextEndpoint(t *testing.T) {
	for base, ok := range map[string]bool{
		"https://gateway.example.com": true,
		"http://127.0.0.1:8080":       true,
		"http://localhost:8080":       true,
		"http://gateway.example.com":  false,
		"ftp://gateway.example.com":   false,
		"not a url":                   false,
	} {
		g := Default().GoalDrift
		g.Enabled, g.BaseURL = true, base
		if err := g.validate(); (err == nil) != ok {
			t.Errorf("%q: err %v, want ok=%v", base, err, ok)
		}
	}
}

func TestGoalDriftNeedsAKeySource(t *testing.T) {
	g := Default().GoalDrift
	g.Enabled, g.APIKeyEnv = true, ""
	if err := g.validate(); err == nil {
		t.Error("enabled with neither api_key_file nor api_key_env validated")
	}
}

func TestGoalDriftKeyFilePrecedesTheEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(" sk-file \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AMBIT_TEST_KEY", "sk-env")
	g := GoalDrift{APIKeyFile: p, APIKeyEnv: "AMBIT_TEST_KEY"}
	if k, err := g.APIKey(); err != nil || k != "sk-file" {
		t.Errorf("key %q, %v; want the file's", k, err)
	}
	g.APIKeyFile = ""
	if k, err := g.APIKey(); err != nil || k != "sk-env" {
		t.Errorf("key %q, %v; want the environment's", k, err)
	}
	g.APIKeyEnv = "AMBIT_TEST_KEY_UNSET"
	if _, err := g.APIKey(); err == nil || !strings.Contains(err.Error(), "AMBIT_TEST_KEY_UNSET") {
		t.Errorf("err %v: want one naming the unset variable", err)
	}
}

func TestDriftThresholdOutOfRangeIsRefused(t *testing.T) {
	c := Default()
	c.DriftThreshold = 0
	if err := c.Validate(); err == nil {
		t.Error("drift_threshold 0 validated: every score, including RELATED, would cross")
	}
}
