package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abijit2626/ambit/internal/mcp"
)

// A server's name becomes a file name in the baseline directory; no name may put it anywhere else.
func FuzzFileNameStaysInTheDirectory(f *testing.F) {
	for _, s := range []string{"github", "../../etc/passwd", "a/b\\c", "..", "", ".hidden", "C:\\x", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, server string) {
		name := fileName(server)
		if strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") || filepath.Base(name) != name {
			t.Fatalf("fileName(%q) = %q escapes or hides in the directory", server, name)
		}
	})
}

// A baseline file on disk may be truncated or edited by hand; observing a listing against it must
// return an error or a result, never panic.
func FuzzObserveWithAnyRecordOnDisk(f *testing.F) {
	f.Add([]byte(`{"schema_v":1,"server":"wiki","tools":{"search":{"metadata_hash":"sha256:x"}},"approved":true}`))
	f.Add([]byte(`{"tools":null}`))
	f.Add([]byte(`{"tools":{"a":{"fields":{"description":"x"}}}}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		dir := t.TempDir()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.path("wiki"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		tools := []mcp.Tool{{Name: "search", Description: "Search the wiki"}, {Name: "publish", Description: "Publish"}}
		_, _ = s.Observe("wiki", mcp.ServerInfo{Name: "wiki"}, tools, true, time.Unix(0, 0))
		_, _ = s.Approve("wiki", "fuzz", time.Unix(1, 0))
	})
}
