package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MCPServer is one entry under mcpServers, as Claude Code reads it.
type MCPServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

// MCPFile is the MCP servers one configuration file declares, under the scope Claude Code reads them in.
type MCPFile struct {
	Path    string
	Scope   string
	Servers map[string]MCPServer
}

// MCPPaths are the files that declare MCP servers for this user in this directory: the project's
// .mcp.json, and ~/.claude.json, which holds the user's servers and each project's local ones.
func MCPPaths(home, cwd string) []string {
	var paths []string
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, ".mcp.json"))
	}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".claude.json"))
	}
	return paths
}

// LoadMCP reads the MCP servers from paths. In ~/.claude.json it reads the user's servers and, when cwd
// is one of its projects, that project's local servers; the rest of that file is not ambit's business.
func LoadMCP(paths []string, cwd string) ([]MCPFile, []Finding) {
	var files []MCPFile
	var problems []Finding
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = append(problems, Finding{Level: Warn, Check: "mcp", Detail: fmt.Sprintf("cannot read %s: %v", p, err)})
			continue
		}
		var doc struct {
			Servers  map[string]MCPServer `json:"mcpServers"`
			Projects map[string]struct {
				Servers map[string]MCPServer `json:"mcpServers"`
			} `json:"projects"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			problems = append(problems, Finding{Level: Fail, Check: "mcp", Detail: fmt.Sprintf("%s is not valid JSON, so Claude Code cannot read its MCP servers: %v", p, err)})
			continue
		}
		scope := "project"
		if filepath.Base(p) == ".claude.json" {
			scope = "user"
		}
		if len(doc.Servers) > 0 {
			files = append(files, MCPFile{Path: p, Scope: scope, Servers: doc.Servers})
		}
		if cwd != "" {
			if proj, ok := doc.Projects[cwd]; ok && len(proj.Servers) > 0 {
				files = append(files, MCPFile{Path: p, Scope: "local", Servers: proj.Servers})
			}
		}
	}
	return files, problems
}

// CheckMCP says which MCP servers mcp-interpose stands in front of. A server it does not wrap has no D4
// baseline and no D5 scan, and its tool calls carry no annotations. Interposing is optional, so a gap is
// a warning, not a failure.
//
// Findings name servers, files and command names, never arguments, headers or URLs: those are where an
// MCP configuration keeps its tokens.
func CheckMCP(files []MCPFile) []Finding {
	var out []Finding
	add := func(level, format string, a ...any) {
		out = append(out, Finding{Level: level, Check: "mcp", Detail: fmt.Sprintf(format, a...)})
	}
	total, wrapped := 0, 0
	for _, f := range files {
		names := make([]string, 0, len(f.Servers))
		for name := range f.Servers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			total++
			s := f.Servers[name]
			where := fmt.Sprintf("%q (%s scope, %s)", name, f.Scope, f.Path)
			if isInterposer(s.Command) {
				wrapped++
				switch server := flagValue(s.Args, "server"); {
				case server == "":
					add(Fail, "%s runs mcp-interpose without -server, so it exits before the server starts", where)
				case server != name:
					add(Warn, "%s is interposed as -server %q; ambitd joins annotations by the key, so this server's tool calls carry none", where, server)
				}
				continue
			}
			remote := s.URL != "" || strings.EqualFold(s.Type, "http") || strings.EqualFold(s.Type, "sse")
			switch {
			case remote && len(s.Headers) > 0:
				add(Warn, "%s is reached over HTTP and not interposed, so D4 and D5 never see its tools; wrap it with mcp-interpose -url, and move its headers to -header-env", where)
			case remote:
				add(Warn, "%s is reached over HTTP and not interposed, so D4 and D5 never see its tools; wrap it with mcp-interpose -url, unless it needs Claude Code's OAuth sign-in, which the interposer cannot run", where)
			case s.Command == "":
				add(Warn, "%s has neither a command nor a url, so Claude Code cannot start it", where)
			default:
				add(Warn, "%s runs %s directly and is not interposed, so D4 and D5 never see its tools", where, filepath.Base(s.Command))
			}
		}
	}
	switch {
	case total == 0:
		add(OK, "no MCP servers are configured for this directory")
	case wrapped == total:
		add(OK, "all %d MCP servers are behind mcp-interpose", total)
	default:
		add(Warn, "%d of %d MCP servers are behind mcp-interpose", wrapped, total)
	}
	return out
}

func mcpPaths(files []MCPFile) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, f := range files {
		if !seen[f.Path] {
			seen[f.Path] = true
			out = append(out, f.Path)
		}
	}
	sort.Strings(out)
	return out
}

func isInterposer(command string) bool {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(command, `\`, "/")))
	return strings.TrimSuffix(base, ".exe") == "mcp-interpose"
}

// flagValue reads -name value, --name value, -name=value or --name=value from the interposer's own flags,
// which end at "--".
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == "--" {
			return ""
		}
		for _, prefix := range []string{"-" + name, "--" + name} {
			if a == prefix && i+1 < len(args) {
				return args[i+1]
			}
			if v, ok := strings.CutPrefix(a, prefix+"="); ok {
				return v
			}
		}
	}
	return ""
}
