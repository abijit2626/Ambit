package egress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Whatever is on disk, Load either refuses it or yields a profile that holds only digests, never more
// than its cap, and still learns.
func FuzzLoadAnyFile(f *testing.F) {
	f.Add([]byte("hmac:a\nhmac:b\n"), uint8(0))
	f.Add([]byte("hmac:a\r\n\r\nhmac:a\n"), uint8(1))
	f.Add([]byte("example.com\n"), uint8(0))
	f.Add([]byte(strings.Repeat("hmac:x", 100)), uint8(2))
	f.Add([]byte{0xff, 0xfe, 0x00}, uint8(0))
	f.Fuzz(func(t *testing.T, content []byte, max uint8) {
		path := filepath.Join(t.TempDir(), "profile.txt")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := Load(path, int(max))
		if err != nil {
			return
		}
		limit := int(max)
		if limit < 1 {
			limit = DefaultMaxDestinations
		}
		if p.Size() > limit {
			t.Fatalf("profile holds %d destinations over a cap of %d", p.Size(), limit)
		}
		for d := range p.seen {
			if !strings.HasPrefix(d, "hmac:") {
				t.Fatalf("profile learned %q, which is not a digest", d)
			}
		}
		if p.Size() < limit {
			if !p.IsNew("hmac:fuzz-new") {
				t.Fatal("a profile with room reports a never-seen destination as known")
			}
			if err := p.Record("hmac:fuzz-new"); err != nil {
				t.Fatal(err)
			}
			if p.IsNew("hmac:fuzz-new") {
				t.Fatal("a recorded destination is still new")
			}
		}
	})
}
