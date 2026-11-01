package collector

import (
	"net"
	"strings"
	"testing"
)

// A sandbox target is the command output's claim, so deniedHost sees whatever a command printed. What
// it returns becomes a destination, so it must be a host or an address and nothing else: no path, no
// whitespace, no port, no upper case.
func FuzzDeniedHostIsAHostOrNothing(f *testing.F) {
	for _, s := range []string{"example.com:443", "[2001:db8::1]:443", "10.0.0.1:8080", "/home/dev/.ssh/id", "a b:1", "[", "x:99999", "2001:db8::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, target string) {
		h := deniedHost(target)
		if h == "" {
			return
		}
		if strings.ContainsAny(h, "/\\ \t\r\n") {
			t.Fatalf("deniedHost(%q) = %q, which is not a host", target, h)
		}
		if h != strings.ToLower(h) {
			t.Fatalf("deniedHost(%q) = %q is not lower case, so one host could be two destinations", target, h)
		}
		if strings.Contains(h, ":") && net.ParseIP(h) == nil {
			t.Fatalf("deniedHost(%q) = %q keeps a colon but is not an address", target, h)
		}
		if deniedHost(h) != h {
			t.Fatalf("deniedHost is not a fixed point on its own output: %q -> %q -> %q", target, h, deniedHost(h))
		}
	})
}
