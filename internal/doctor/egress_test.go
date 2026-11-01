package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/egress"
)

func TestEgressFinding(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var full strings.Builder
	for i := 0; i < egress.DefaultMaxDestinations; i++ {
		fmt.Fprintf(&full, "hmac:%d\n", i)
	}
	for _, c := range []struct {
		name, path, level, want string
	}{
		{"missing", filepath.Join(dir, "absent.txt"), OK, "creates it on the endpoint's first contact"},
		{"healthy", write("ok.txt", "hmac:a\nhmac:b\nhmac:a\n"), OK, "holds 2 destinations"},
		{"damaged", write("bad.txt", "hmac:a\n{\"kind\":\"tool_pre\"}\n"), Fail, "moved aside"},
		{"full", write("full.txt", full.String()), Warn, "no longer reported"},
	} {
		got := egressFinding(c.path)
		if got.Check != "egress" || got.Level != c.level || !strings.Contains(got.Detail, c.want) {
			t.Errorf("%s: %+v, want %s containing %q", c.name, got, c.level, c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "absent.txt")); !os.IsNotExist(err) {
		t.Error("doctor created the profile; it must only read")
	}
}

func TestEgressFindingUnreadableWarns(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root Unix account for a permission error")
	}
	p := filepath.Join(t.TempDir(), "profile.txt")
	if err := os.WriteFile(p, []byte("hmac:a\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	got := egressFinding(p)
	if got.Level != Warn || !strings.Contains(got.Detail, "account ambitd runs as") {
		t.Errorf("finding = %+v", got)
	}
}
