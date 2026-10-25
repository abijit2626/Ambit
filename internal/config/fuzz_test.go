package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A config file is operator input but often hand-edited; any content must load or fail with an error.
func FuzzLoadAnyFile(f *testing.F) {
	f.Add([]byte(`{"hook_addr":"127.0.0.1:7777","health_seconds":60,"latency_budget_ms":5}`))
	f.Add([]byte(`{"hook_addr":"0.0.0.0:7777"}`))
	f.Add([]byte(`{"mcp_tool_labels":{"wiki":{"*":["sensitive","bogus"]}}}`))
	f.Add([]byte(`{"health_seconds":-1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err != nil {
			return
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Load returned a config that fails Validate: %v", err)
		}
	})
}
