// Package config loads ambitd configuration.
//
// Configuration deliberately does NOT arrive over the Wazuh channel. Wazuh's
// centralized configuration exists and would be convenient, but using it would
// let anyone with manager access — including an MSSP — rewrite what ambitd
// observes and, from M3, what it denies. Separate path, separate trust root. See
// docs/02-architecture.md.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
)

// Config is ambitd's full configuration.
type Config struct {
	// HookAddr is the loopback address the hook endpoint binds. Must match the
	// url in the managed-settings hook entry.
	HookAddr string `json:"hook_addr"`

	// OTLPAddr is the loopback address the OTLP/HTTP receiver binds. 4318 is the
	// OTLP/HTTP default; 4317 is gRPC and would be the wrong port for a receiver
	// that only speaks http/json.
	OTLPAddr string `json:"otlp_addr"`
	// OTLPEnabled turns the second stream on. Off means Claude Code's telemetry
	// has nowhere to go, so the managed bundle must not set OTEL_* either —
	// pointing an exporter at a dead port is a misconfiguration, not a no-op.
	OTLPEnabled bool `json:"otlp_enabled"`

	// EventsPath is the Wazuh-bound sink: filtered, flattened events, tailed by
	// the Wazuh agent with log_format json.
	EventsPath string `json:"events_path"`
	// TrajectoryPath is the local spool: every event, rich schema, never
	// indexed. The investigation corpus.
	TrajectoryPath string `json:"trajectory_path"`

	// EventsMaxBytes and EventsMaxFiles bound the Wazuh-bound sink.
	EventsMaxBytes int64 `json:"events_max_bytes"`
	EventsMaxFiles int   `json:"events_max_files"`
	// TrajectoryMaxBytes and TrajectoryMaxFiles bound the spool. Larger than the
	// events sink because it holds everything.
	TrajectoryMaxBytes int64 `json:"trajectory_max_bytes"`
	TrajectoryMaxFiles int   `json:"trajectory_max_files"`

	// FingerprintKeyPath holds the per-org HMAC key. The key stays ours and is
	// never shared with a monitoring firm: they need equality matching, not
	// resolution.
	FingerprintKeyPath string `json:"fingerprint_key_path"`

	// EndpointID and Org identify this endpoint in the fleet.
	EndpointID string `json:"endpoint_id"`
	UserID     string `json:"user_id"`
	OrgID      string `json:"org_id"`

	// Home overrides the detected home directory, for testing.
	Home string `json:"home"`
	// ExtraUntrustedPaths are operator-configured path fragments treated as
	// untrusted content.
	ExtraUntrustedPaths []string `json:"extra_untrusted_paths"`
	// TrustedRepoPaths are path prefixes whose CLAUDE.md files are trusted. An
	// instruction file outside these is a D8 candidate.
	TrustedRepoPaths []string `json:"trusted_repo_paths"`
	// TrustedMCPServers are explicitly classified servers. A server not listed
	// here is treated as untrusted; a server's own annotations never move it
	// onto this list.
	TrustedMCPServers []string `json:"trusted_mcp_servers"`

	// SampleRate is the fraction of uninteresting tool events that cross anyway,
	// so the SIEM holds enough ordinary traffic to baseline against.
	SampleRate float64 `json:"sample_rate"`
	// DriftThreshold is unused in M0; goal-drift scoring arrives in M4.
	DriftThreshold float64 `json:"drift_threshold"`

	// HealthInterval is how often ambitd emits an ambitd_health event. This is
	// the heartbeat half of D7: SCA's p:ambitd check cannot tell a wedged daemon
	// from a healthy one, so a stale heartbeat with the process present is what
	// distinguishes them.
	HealthInterval time.Duration `json:"-"`
	HealthSeconds  int           `json:"health_seconds"`

	// LatencyBudget is the hook response target.
	LatencyBudget   time.Duration `json:"-"`
	LatencyBudgetMS int           `json:"latency_budget_ms"`

	// Enforce must be false in M0. It exists so the milestone boundary is
	// explicit in configuration rather than implied by which binary is deployed.
	Enforce bool `json:"enforce"`
}

// Default returns the M0 defaults.
func Default() Config {
	return Config{
		HookAddr:           "127.0.0.1:7777",
		EventsPath:         defaultPath("events.jsonl"),
		TrajectoryPath:     defaultPath("trajectory.jsonl"),
		EventsMaxBytes:     64 << 20,
		EventsMaxFiles:     8,
		TrajectoryMaxBytes: 256 << 20,
		TrajectoryMaxFiles: 16,
		FingerprintKeyPath: defaultPath("fingerprint.key"),
		SampleRate:         0.005,
		DriftThreshold:     0.7,
		HealthSeconds:      60,
		LatencyBudgetMS:    5,
		Enforce:            false,
	}
}

func defaultPath(name string) string {
	if runtime.GOOS == "darwin" {
		return "/usr/local/var/ambit/" + name
	}
	return "/var/lib/ambit/" + name
}

// Load reads a config file, falling back to defaults for absent fields. A
// missing file is not an error: the defaults are a working M0 configuration.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		cfg.derive()
		return cfg, cfg.Validate()
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg.derive()
		return cfg, cfg.Validate()
	}
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.derive()
	return cfg, cfg.Validate()
}

func (c *Config) derive() {
	c.HealthInterval = time.Duration(c.HealthSeconds) * time.Second
	c.LatencyBudget = time.Duration(c.LatencyBudgetMS) * time.Millisecond
	if c.Home == "" {
		c.Home, _ = os.UserHomeDir()
	}
}

// Validate rejects configurations that would break a documented invariant.
func (c *Config) Validate() error {
	if c.HookAddr == "" {
		return errors.New("config: hook_addr is required")
	}
	if c.OTLPEnabled && c.OTLPAddr == "" {
		return errors.New("config: otlp_addr is required when otlp_enabled is true")
	}
	if c.OTLPEnabled && c.OTLPAddr == c.HookAddr {
		return errors.New("config: otlp_addr and hook_addr must differ")
	}
	if c.EventsPath == "" || c.TrajectoryPath == "" {
		return errors.New("config: events_path and trajectory_path are required")
	}
	if c.EventsPath == c.TrajectoryPath {
		// They carry different representations with different retention and
		// different audiences: the events sink goes to Wazuh and onward to a
		// monitoring firm, the spool never leaves.
		return errors.New("config: events_path and trajectory_path must differ")
	}
	if c.SampleRate < 0 || c.SampleRate > 1 {
		return fmt.Errorf("config: sample_rate %v out of range [0,1]", c.SampleRate)
	}
	if c.HealthSeconds <= 0 {
		return errors.New("config: health_seconds must be positive; the heartbeat is D7's fine half")
	}
	return nil
}

// TrustedMCPSet returns the trusted servers as a set.
func (c *Config) TrustedMCPSet() map[string]bool {
	m := make(map[string]bool, len(c.TrustedMCPServers))
	for _, s := range c.TrustedMCPServers {
		m[s] = true
	}
	return m
}

// LoadOrCreateFingerprintKey reads the HMAC key, creating one if absent.
//
// Rotating this key breaks equality matching against every previously stored
// fingerprint, so it is created once and left alone. Callers are responsible for
// backing it up: losing it does not lose events, but it does make historical
// digests unmatchable against new ones.
func LoadOrCreateFingerprintKey(path string, gen func() ([]byte, error)) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) < 32 {
			return nil, fmt.Errorf("fingerprint key %s is too short (%d bytes, want >= 32)", path, len(raw))
		}
		return raw, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read fingerprint key: %w", err)
	}
	key, err := gen()
	if err != nil {
		return nil, fmt.Errorf("generate fingerprint key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write fingerprint key: %w", err)
	}
	return key, nil
}
