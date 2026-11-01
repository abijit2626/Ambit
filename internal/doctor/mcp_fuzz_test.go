package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Whatever is in an MCP configuration file, doctor reads it without panicking.
func FuzzLoadMCPAnyFile(f *testing.F) {
	f.Add([]byte(`{"mcpServers":{"a":{"command":"mcp-interpose","args":["-server","a","--","x"]}}}`), "/p")
	f.Add([]byte(`{"projects":{"/p":{"mcpServers":{"b":{"type":"sse","url":"https://x"}}}}}`), "/p")
	f.Add([]byte(`{"mcpServers":{"c":{"command":7}}}`), "")
	f.Add([]byte(`[]`), "/")
	f.Fuzz(func(t *testing.T, content []byte, cwd string) {
		dir := t.TempDir()
		paths := []string{filepath.Join(dir, ".mcp.json"), filepath.Join(dir, ".claude.json")}
		for _, p := range paths {
			if err := os.WriteFile(p, content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		files, problems := LoadMCP(paths, cwd)
		for _, fd := range append(problems, CheckMCP(files)...) {
			if fd.Check != "mcp" || (fd.Level != OK && fd.Level != Warn && fd.Level != Fail) {
				t.Fatalf("malformed finding %+v", fd)
			}
		}
	})
}

// A finding names servers, files and command names. Arguments, header values and URLs are where an MCP
// configuration keeps its tokens, so none of them may appear in one, whatever the server looks like.
func FuzzMCPFindingsNeverRepeatASecret(f *testing.F) {
	f.Add("github", "npx", "ghp_0123456789abcdef", "Bearer tok-0123456789", "https://mcp.example.com/x?key=k-0123456789", "http")
	f.Add("wiki", "mcp-interpose", "Authorization: Bearer tok-0123456789", "Basic dXNlcjpwYXNz", "", "")
	f.Add("x", "", "", "", "http://h/?t=secret-secret", "sse")
	f.Fuzz(func(t *testing.T, name, command, arg, header, url, typ string) {
		if name == "" {
			return
		}
		// -server's value is the one argument a finding may name, so it is the key here; the secret is
		// where tokens really go, in the interposer's -header and the wrapped command's arguments.
		server := map[string]any{"command": command, "args": []string{"-server", name, "-header", arg, "--", "npx", arg}, "type": typ}
		if url != "" {
			server["url"] = url
		}
		if header != "" {
			server["headers"] = map[string]string{"Authorization": header}
		}
		raw, err := json.Marshal(map[string]any{"mcpServers": map[string]any{name: server}})
		if err != nil {
			return
		}
		dir := t.TempDir()
		p := filepath.Join(dir, ".mcp.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		files, problems := LoadMCP([]string{p}, "")
		findings := append(problems, CheckMCP(files)...)
		for _, secret := range []string{arg, header, url} {
			// A value that is also part of what a finding may name proves nothing either way.
			if len(secret) < 8 || strings.Contains(name, secret) || strings.Contains(command, secret) ||
				strings.Contains(p, secret) || strings.Contains(filepath.Base(command), secret) {
				continue
			}
			for _, fd := range findings {
				if strings.Contains(fd.Detail, secret) {
					t.Fatalf("finding repeats %q: %s", secret, fd.Detail)
				}
			}
		}
	})
}
