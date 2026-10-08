package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/abijit2626/ambit/internal/fsperm"
)

type Config struct {
	HookAddr string `json:"hook_addr"`

	OTLPAddr string `json:"otlp_addr"`

	OTLPEnabled bool `json:"otlp_enabled"`

	EventsPath string `json:"events_path"`

	TrajectoryPath string `json:"trajectory_path"`

	EventsMaxBytes int64 `json:"events_max_bytes"`
	EventsMaxFiles int   `json:"events_max_files"`

	TrajectoryMaxBytes int64 `json:"trajectory_max_bytes"`
	TrajectoryMaxFiles int   `json:"trajectory_max_files"`

	BaselineDir string `json:"baseline_dir"`

	FingerprintKeyPath string `json:"fingerprint_key_path"`

	EndpointID string `json:"endpoint_id"`
	UserID     string `json:"user_id"`
	OrgID      string `json:"org_id"`

	Home string `json:"home"`

	detectedHome string

	ExtraUntrustedPaths []string `json:"extra_untrusted_paths"`

	TrustedRepoPaths []string `json:"trusted_repo_paths"`

	TrustedMCPServers []string `json:"trusted_mcp_servers"`

	MCPToolLabels map[string]map[string][]string `json:"mcp_tool_labels"`

	TrustedContentDomains []string `json:"trusted_content_domains"`

	SampleRate float64 `json:"sample_rate"`

	DriftThreshold float64 `json:"drift_threshold"`

	HealthInterval time.Duration `json:"-"`
	HealthSeconds  int           `json:"health_seconds"`

	LatencyBudget   time.Duration `json:"-"`
	LatencyBudgetMS int           `json:"latency_budget_ms"`

	Enforce bool `json:"enforce"`
}

func Default() Config {
	return Config{
		HookAddr:           "127.0.0.1:7777",
		EventsPath:         defaultPath("events.jsonl"),
		TrajectoryPath:     defaultPath("trajectory.jsonl"),
		EventsMaxBytes:     64 << 20,
		EventsMaxFiles:     8,
		TrajectoryMaxBytes: 256 << 20,
		TrajectoryMaxFiles: 16,
		BaselineDir:        defaultBaselineDir(runtime.GOOS, os.UserHomeDir),
		FingerprintKeyPath: defaultPath("fingerprint.key"),
		SampleRate:         0.005,
		DriftThreshold:     0.7,
		HealthSeconds:      60,
		LatencyBudgetMS:    5,
		Enforce:            false,
	}
}

func defaultPath(name string) string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/var/ambit/" + name
	case "windows":

		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "ambit", name)
	}
	return "/var/lib/ambit/" + name
}

func defaultBaselineDir(goos string, userHome func() (string, error)) string {
	if goos == "windows" {
		if home, err := userHome(); err == nil && home != "" {
			return filepath.Join(home, ".ambit", "baselines")
		}
	}
	return defaultPath("baselines")
}

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
		c.detectedHome = c.Home
	}
}

func (c Config) HomeIsDetected() bool {
	return c.Home == "" || (c.detectedHome != "" && c.Home == c.detectedHome)
}

func (c *Config) Validate() error {
	if err := validateToolLabels(c.MCPToolLabels); err != nil {
		return err
	}
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
	if samePath(c.EventsPath, c.TrajectoryPath) {

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

func (c *Config) TrustedMCPSet() map[string]bool {
	m := make(map[string]bool, len(c.TrustedMCPServers))
	for _, s := range c.TrustedMCPServers {
		m[s] = true
	}
	return m
}

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

	if err := fsperm.PrivateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("create fingerprint key dir: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write fingerprint key: %w", err)
	}
	return key, nil
}

var caseInsensitiveFS = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

func samePath(a, b string) bool {
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if ca == cb || (caseInsensitiveFS && strings.EqualFold(ca, cb)) {
		return true
	}
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

const (
	LabelUntrusted = "untrusted"

	LabelSensitive = "sensitive"

	LabelReadOnly = "read_only"
)

var knownLabels = map[string]bool{LabelUntrusted: true, LabelSensitive: true, LabelReadOnly: true}

type ToolLabels struct {
	Untrusted, Sensitive, ReadOnly bool

	Names []string
}

func (c *Config) ToolLabels(server, tool string) (ToolLabels, bool) {
	entries, ok := c.MCPToolLabels[server]
	if !ok {
		return ToolLabels{}, false
	}
	var tl ToolLabels
	matched := false
	seen := map[string]bool{}
	for pattern, labels := range entries {
		if hit, _ := path.Match(pattern, tool); !hit {
			continue
		}
		matched = true
		for _, l := range labels {
			seen[l] = true
		}
	}
	if !matched {
		return ToolLabels{}, false
	}
	tl.Untrusted, tl.Sensitive, tl.ReadOnly = seen[LabelUntrusted], seen[LabelSensitive], seen[LabelReadOnly]
	for l := range seen {
		tl.Names = append(tl.Names, l)
	}
	sort.Strings(tl.Names)
	return tl, true
}

func validateToolLabels(m map[string]map[string][]string) error {
	for server, entries := range m {
		if server == "" {
			return errors.New("config: mcp_tool_labels has an empty server name")
		}
		for pattern, labels := range entries {
			if _, err := path.Match(pattern, ""); err != nil {
				return fmt.Errorf("config: mcp_tool_labels[%q]: bad tool pattern %q: %w", server, pattern, err)
			}
			for _, l := range labels {
				if !knownLabels[l] {
					return fmt.Errorf("config: mcp_tool_labels[%q][%q]: unknown label %q (want %s, %s or %s)",
						server, pattern, l, LabelUntrusted, LabelSensitive, LabelReadOnly)
				}
			}
		}
	}
	return nil
}
