package collector

import (
	"path/filepath"
	"testing"

	"github.com/abijit2626/ambit/internal/egress"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/hook"
)

func newEgressCollector(t *testing.T, path string) (*Collector, *memSink) {
	t.Helper()
	c, events, _ := newTestCollector(t)
	p, err := egress.Load(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.egress = p
	return c, events
}

func bashPre(sid, command string) *hook.Payload {
	return pre(sid, "p1", "Bash", map[string]any{"command": command})
}

func egressEvents(t *testing.T, events *memSink) []map[string]any {
	t.Helper()
	return siemLines(t, events, event.KindEgressDestination)
}

func TestFirstContactWithADestinationIsReportedOnce(t *testing.T) {
	c, events := newEgressCollector(t, filepath.Join(t.TempDir(), "profile.txt"))

	c.Handle(bashPre("s1", "curl -sS https://api.new-vendor.test/v1/status"))
	got := egressEvents(t, events)
	if len(got) != 1 {
		t.Fatalf("egress_destination events = %d, want 1", len(got))
	}
	m := got[0]
	want := c.ext.Digest(features.Registrable("api.new-vendor.test"))
	if m["egress_source"] != event.EgressSourceBash || m["egress_dest_digest"] != want {
		t.Errorf("event = source %v digest %v, want bash %s", m["egress_source"], m["egress_dest_digest"], want)
	}
	if m["session_id"] != "s1" || m["tool_name"] != "Bash" {
		t.Errorf("the event lost its session or tool: %v", m)
	}

	// another host under the same registrable domain, in another session, is the same destination
	c.Handle(bashPre("s2", "curl https://cdn.new-vendor.test/x"))
	if n := len(egressEvents(t, events)); n != 1 {
		t.Errorf("%d events after a second contact, want 1: the profile is per endpoint, not per session", n)
	}
}

func TestProfileOutlivesTheCollector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.txt")
	c, _ := newEgressCollector(t, path)
	c.Handle(bashPre("s1", "curl https://api.new-vendor.test/"))

	again, events := newEgressCollector(t, path)
	again.Handle(bashPre("s1", "curl https://api.new-vendor.test/"))
	if n := len(egressEvents(t, events)); n != 0 {
		t.Errorf("%d events after a restart, want 0: a destination learned before must stay learned", n)
	}
}

func TestOnlyNetworkCommandsCount(t *testing.T) {
	c, events := newEgressCollector(t, filepath.Join(t.TempDir(), "profile.txt"))
	c.Handle(bashPre("s1", "grep -r new-vendor.test docs/"))
	c.Handle(pre("s1", "p1", "Write", map[string]any{"file_path": "/home/dev/src/myrepo/notes.md", "content": "see https://api.new-vendor.test"}))
	if n := len(egressEvents(t, events)); n != 0 {
		t.Errorf("%d events for text that only names a host, want 0", n)
	}
}

func TestAddressesAreDestinationsOfTheirOwn(t *testing.T) {
	c, events := newEgressCollector(t, filepath.Join(t.TempDir(), "profile.txt"))
	c.Handle(bashPre("s1", "curl http://10.0.3.4/health"))
	c.Handle(bashPre("s1", "curl http://192.168.3.4/health"))
	got := egressEvents(t, events)
	if len(got) != 2 || got[0]["egress_dest_digest"] == got[1]["egress_dest_digest"] {
		t.Fatalf("two addresses sharing their last octets must be two destinations: %v", got)
	}
}

func TestSandboxRefusedHostIsADestination(t *testing.T) {
	c, events := newEgressCollector(t, filepath.Join(t.TempDir(), "profile.txt"))
	c.Handle(denied("s1"))
	got := egressEvents(t, events)
	if len(got) != 1 || got[0]["egress_source"] != event.EgressSourceSandbox {
		t.Fatalf("egress events for a refused host = %v, want one from the sandbox", got)
	}
	if want := c.ext.Digest("example.com"); got[0]["egress_dest_digest"] != want {
		t.Errorf("digest = %v, want the registrable domain's %s", got[0]["egress_dest_digest"], want)
	}
	if n := len(siemLines(t, events, event.KindSandboxDenial)); n != 1 {
		t.Errorf("sandbox_denial events = %d, want the existing one alongside", n)
	}
}

// A command and its denial name one host; the two sources must agree on its digest, or every refused
// destination would be reported twice.
func TestCommandAndDenialAgreeOnTheDestination(t *testing.T) {
	c, events := newEgressCollector(t, filepath.Join(t.TempDir(), "profile.txt"))
	c.Handle(bashPre("s1", "curl -sS https://www.example.com"))
	c.Handle(denied("s1"))
	if got := egressEvents(t, events); len(got) != 1 || got[0]["egress_source"] != event.EgressSourceBash {
		t.Errorf("events = %v, want only the command's", got)
	}
}

func TestRefusedReportIsNotLearned(t *testing.T) {
	sink := &refusable{memSink: &memSink{}, refuse: true}
	c, _ := newEgressCollector(t, filepath.Join(t.TempDir(), "profile.txt"))
	c.events = sink

	c.Handle(bashPre("s1", "curl https://api.new-vendor.test/"))
	if c.egress.Size() != 0 {
		t.Fatal("a destination whose event the sink refused was learned")
	}
	sink.refuse = false
	c.Handle(bashPre("s1", "curl https://api.new-vendor.test/"))
	if n := len(egressEvents(t, sink.memSink)); n != 1 {
		t.Errorf("%d events once the sink recovered, want 1", n)
	}
}

func TestNoProfileNoEvents(t *testing.T) {
	c, events, _ := newTestCollector(t)
	c.Handle(bashPre("s1", "curl https://api.new-vendor.test/"))
	c.Handle(denied("s1"))
	if n := len(egressEvents(t, events)); n != 0 {
		t.Errorf("%d events with no profile, want 0", n)
	}
}

func TestDeniedHost(t *testing.T) {
	for in, want := range map[string]string{
		"example.com:443":    "example.com",
		"Example.COM":        "example.com",
		"10.0.0.1:8080":      "10.0.0.1",
		"[2001:db8::1]:443":  "2001:db8::1",
		"[broken":            "",
		"/home/dev/.ssh/key": "",
		"":                   "",
		"host:notaport":      "",
		"2001:db8::1":        "2001:db8::1",
	} {
		if got := deniedHost(in); got != want {
			t.Errorf("deniedHost(%q) = %q, want %q", in, got, want)
		}
	}
}
