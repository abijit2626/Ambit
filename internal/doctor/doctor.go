// Package doctor is `ambitd doctor`: it reads the Claude Code settings an endpoint will run with and says
// whether ambitd will hear from them. Each check is one that fails quietly in practice: a hook that points
// elsewhere, an OTel exporter speaking protobuf, and Claude Code's sandbox refusing http hooks to 127.0.0.1
// (observed on v2.1.310; docs/06 blocker 7).
package doctor

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/abijit2626/ambit/internal/config"
)

const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
)

// The events ambitd needs over http. SessionStart is not here: Claude Code delivers it only to a command
// hook, which the bundles register as `ambitd hook-forward`.
var httpEvents = []string{"UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure"}

type Finding struct {
	Level  string `json:"level"`
	Check  string `json:"check"`
	Detail string `json:"detail"`
}

type File struct {
	Path     string
	Settings map[string]json.RawMessage
}

type hookEntry struct {
	Hooks []struct {
		Type    string `json:"type"`
		URL     string `json:"url"`
		Command string `json:"command"`
	} `json:"hooks"`
}

type sandbox struct {
	Enabled *bool `json:"enabled"`
	Network struct {
		AllowedDomains []string `json:"allowedDomains"`
	} `json:"network"`
}

// Check reports on the merged picture of the settings files against ambitd's hook address. It does not
// reproduce Claude Code's full precedence rules: a hook or allowed domain in any file counts, and the
// sandbox counts as on if any file turns it on.
func Check(files []File, hookAddr string, otlpEnabled bool) []Finding {
	var out []Finding
	add := func(level, check, format string, a ...any) {
		out = append(out, Finding{Level: level, Check: check, Detail: fmt.Sprintf(format, a...)})
	}
	if len(files) == 0 {
		add(Fail, "settings", "no Claude Code settings file found, so no hook sends anything to ambitd")
		return out
	}

	url := "http://" + hookAddr + "/hook"
	covered := map[string]bool{}
	forward := false
	sandboxOn := false
	allowed := map[string]bool{}
	protocol := ""
	for _, f := range files {
		var hooks map[string]json.RawMessage
		_ = json.Unmarshal(f.Settings["hooks"], &hooks)
		for ev, raw := range hooks {
			if strings.HasPrefix(ev, "_") {
				continue
			}
			var entries []hookEntry
			if json.Unmarshal(raw, &entries) != nil {
				continue
			}
			for _, e := range entries {
				for _, h := range e.Hooks {
					if h.Type == "http" && strings.TrimRight(h.URL, "/") == url {
						covered[ev] = true
					}
					if h.Type == "command" && ev == "SessionStart" && strings.Contains(h.Command, "hook-forward") {
						forward = true
					}
				}
			}
		}
		var sb sandbox
		if json.Unmarshal(f.Settings["sandbox"], &sb) == nil {
			if sb.Enabled != nil && *sb.Enabled {
				sandboxOn = true
			}
			for _, d := range sb.Network.AllowedDomains {
				allowed[strings.ToLower(d)] = true
			}
		}
		var env map[string]json.RawMessage
		if json.Unmarshal(f.Settings["env"], &env) == nil {
			var v string
			if json.Unmarshal(env["OTEL_EXPORTER_OTLP_PROTOCOL"], &v) == nil && v != "" {
				protocol = v
			}
		}
	}

	var missing []string
	for _, ev := range httpEvents {
		if !covered[ev] {
			missing = append(missing, ev)
		}
	}
	if len(missing) == 0 {
		add(OK, "hooks", "%s go to %s", strings.Join(httpEvents, ", "), url)
	} else {
		add(Fail, "hooks", "no http hook sends %s to %s", strings.Join(missing, ", "), url)
	}
	if forward {
		add(OK, "session_start", "SessionStart runs ambitd hook-forward")
	} else {
		add(Warn, "session_start", "SessionStart has no ambitd hook-forward command hook; Claude Code does not deliver it over http, so session_start events will be missing")
	}

	if sandboxOn {
		if allowed["127.0.0.1"] || allowed["localhost"] {
			add(OK, "sandbox", "the sandbox is on and 127.0.0.1 is an allowed domain, so http hooks get through")
		} else {
			add(Fail, "sandbox", "the sandbox is on and 127.0.0.1 is not in sandbox.network.allowedDomains: Claude Code sends http hooks through the sandbox proxy, which refuses it, so ambitd hears only SessionStart (docs/06 blocker 7)")
		}
	} else {
		add(OK, "sandbox", "the sandbox is not turned on in these files, so it does not stand between the hooks and ambitd")
	}

	if otlpEnabled {
		switch protocol {
		case "http/json":
			add(OK, "otel", "OTel exports use http/json")
		case "":
			add(Warn, "otel", "ambitd's OTLP receiver is on but no settings file sets OTEL_EXPORTER_OTLP_PROTOCOL; it must be http/json")
		default:
			add(Fail, "otel", "OTEL_EXPORTER_OTLP_PROTOCOL is %q; ambitd accepts only http/json, and rejects the rest", protocol)
		}
	}
	return out
}

// DefaultPaths are the settings files Claude Code reads for this user and machine, most general first.
func DefaultPaths(home, cwd string) []string {
	var managed string
	switch runtime.GOOS {
	case "darwin":
		managed = "/Library/Application Support/ClaudeCode/managed-settings.json"
	case "windows":
		base := os.Getenv("ProgramW6432")
		if base == "" {
			base = os.Getenv("ProgramFiles")
		}
		managed = filepath.Join(base, "ClaudeCode", "managed-settings.json")
	default:
		managed = "/etc/claude-code/managed-settings.json"
	}
	paths := []string{managed}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".claude", "settings.json"))
	}
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, ".claude", "settings.json"), filepath.Join(cwd, ".claude", "settings.local.json"))
	}
	return paths
}

func Load(paths []string) ([]File, []Finding) {
	var files []File
	var problems []Finding
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = append(problems, Finding{Level: Warn, Check: "settings", Detail: fmt.Sprintf("cannot read %s: %v", p, err)})
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			problems = append(problems, Finding{Level: Fail, Check: "settings", Detail: fmt.Sprintf("%s is not valid JSON, so Claude Code ignores it: %v", p, err)})
			continue
		}
		files = append(files, File{Path: p, Settings: m})
	}
	return files, problems
}

func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "ambitd config JSON (for hook_addr and otlp_enabled)")
	var extra multi
	fs.Var(&extra, "settings", "a Claude Code settings file to read as well (repeatable)")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "ambitd doctor:", err)
		return 1
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	paths := append(DefaultPaths(home, cwd), extra...)
	files, findings := Load(paths)
	findings = append(findings, healthFinding(cfg.HookAddr))
	findings = append(findings, Check(files, cfg.HookAddr, cfg.OTLPEnabled)...)

	worst := 0
	for _, f := range findings {
		worst = max(worst, rank(f.Level))
	}
	if *asJSON {
		read := make([]string, 0, len(files))
		for _, f := range files {
			read = append(read, f.Path)
		}
		sort.Strings(read)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"settings_read": read, "findings": findings})
	} else {
		fmt.Fprintln(stdout, "ambitd doctor")
		for _, f := range files {
			fmt.Fprintf(stdout, "  read %s\n", f.Path)
		}
		for _, f := range findings {
			fmt.Fprintf(stdout, "  [%-4s] %-13s %s\n", strings.ToUpper(f.Level), f.Check, f.Detail)
		}
	}
	if worst == rank(Fail) {
		return 1
	}
	return 0
}

func healthFinding(addr string) Finding {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return Finding{Level: Fail, Check: "ambitd", Detail: fmt.Sprintf("no answer on %s: %v", addr, err)}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Finding{Level: Fail, Check: "ambitd", Detail: fmt.Sprintf("%s/healthz answered %d", addr, resp.StatusCode)}
	}
	return Finding{Level: OK, Check: "ambitd", Detail: "answers on " + addr}
}

func rank(level string) int {
	switch level {
	case Fail:
		return 2
	case Warn:
		return 1
	}
	return 0
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
