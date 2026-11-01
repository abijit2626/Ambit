package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMCP(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mcpFindings(t *testing.T, project, user, cwd string) []Finding {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	if project != "" {
		paths = append(paths, writeMCP(t, dir, ".mcp.json", project))
	}
	if user != "" {
		paths = append(paths, writeMCP(t, dir, ".claude.json", user))
	}
	files, problems := LoadMCP(paths, cwd)
	return append(problems, CheckMCP(files)...)
}

func detailWith(fs []Finding, level, needle string) bool {
	for _, f := range fs {
		if f.Check == "mcp" && f.Level == level && strings.Contains(f.Detail, needle) {
			return true
		}
	}
	return false
}

func TestEveryServerInterposedPasses(t *testing.T) {
	got := mcpFindings(t, `{"mcpServers":{
		"github":{"command":"mcp-interpose","args":["-server","github","--","npx","-y","@modelcontextprotocol/server-github"]},
		"wiki":{"command":"/usr/local/bin/mcp-interpose","args":["-server=wiki","-url","https://wiki.example.com/mcp"]}}}`, "", "")
	if !detailWith(got, OK, "all 2 MCP servers are behind mcp-interpose") {
		t.Fatalf("findings = %+v", got)
	}
	for _, f := range got {
		if f.Level != OK {
			t.Errorf("unexpected finding %+v", f)
		}
	}
}

func TestUninterposedServersWarn(t *testing.T) {
	got := mcpFindings(t, `{"mcpServers":{
		"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/home/dev"]},
		"remote":{"type":"http","url":"https://mcp.example.com/mcp?key=SECRET-IN-URL","headers":{"Authorization":"Bearer SECRET-IN-HEADER"}},
		"oauth":{"type":"sse","url":"https://other.example.com/sse"},
		"wrapped":{"command":"mcp-interpose","args":["-server","wrapped","--","node","server.js"]}}}`, "", "")
	for _, want := range []struct{ level, needle string }{
		{Warn, `"fs" (project scope`},
		{Warn, "runs npx directly"},
		{Warn, `"remote" (project scope`},
		{Warn, "move its headers to -header-env"},
		{Warn, "OAuth sign-in"},
		{Warn, "1 of 4 MCP servers are behind mcp-interpose"},
	} {
		if !detailWith(got, want.level, want.needle) {
			t.Errorf("no %s finding containing %q in %+v", want.level, want.needle, got)
		}
	}
	for _, f := range got {
		if strings.Contains(f.Detail, "SECRET") || strings.Contains(f.Detail, "server-filesystem") {
			t.Errorf("a finding repeats an argument, header or URL, which is where tokens live: %s", f.Detail)
		}
	}
}

func TestInterposerNameMustMatchTheKey(t *testing.T) {
	got := mcpFindings(t, `{"mcpServers":{
		"github":{"command":"mcp-interpose","args":["-server","gh","--","npx","server-github"]},
		"broken":{"command":"mcp-interpose.exe","args":["--","node","x.js","-server","broken"]}}}`, "", "")
	if !detailWith(got, Warn, `interposed as -server "gh"`) {
		t.Errorf("a -server name that differs from the key must warn: %+v", got)
	}
	if !detailWith(got, Fail, "without -server") {
		t.Errorf("-server after -- belongs to the wrapped server, so the interposer has none: %+v", got)
	}
}

func TestUserAndLocalScopesAreRead(t *testing.T) {
	cwd := "/home/dev/src/myrepo"
	got := mcpFindings(t, "", `{"mcpServers":{"mine":{"command":"uvx","args":["mcp-server-time"]}},
		"projects":{"/home/dev/src/myrepo":{"mcpServers":{"here":{"command":"mcp-interpose","args":["-server","here","--","x"]}}},
		            "/elsewhere":{"mcpServers":{"there":{"command":"node"}}}},
		"oauthAccount":{"emailAddress":"dev@example.com"}}`, cwd)
	if !detailWith(got, Warn, `"mine" (user scope`) {
		t.Errorf("the user's own servers were not read: %+v", got)
	}
	if !detailWith(got, Warn, "1 of 2 MCP servers") {
		t.Errorf("the local server for this directory was not counted, or another project's was: %+v", got)
	}
	if detailWith(got, Warn, `"there"`) {
		t.Error("another project's server was reported")
	}
}

func TestNoMCPServersIsFine(t *testing.T) {
	got := mcpFindings(t, `{"mcpServers":{}}`, `{"projects":{}}`, "/x")
	if !detailWith(got, OK, "no MCP servers") {
		t.Errorf("findings = %+v", got)
	}
}

func TestBrokenMCPFileFails(t *testing.T) {
	got := mcpFindings(t, `{"mcpServers":`, "", "")
	if !detailWith(got, Fail, "not valid JSON") {
		t.Errorf("findings = %+v", got)
	}
}

func TestFlagValue(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-server", "a"}, "a"},
		{[]string{"--server", "a"}, "a"},
		{[]string{"-server=a"}, "a"},
		{[]string{"-v", "--server=a", "--", "x"}, "a"},
		{[]string{"--", "-server", "a"}, ""},
		{[]string{"-server"}, ""},
	} {
		if got := flagValue(c.args, "server"); got != c.want {
			t.Errorf("flagValue(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}
