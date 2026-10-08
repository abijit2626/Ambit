package collector

import (
	"testing"

	"github.com/abijit2626/ambit/internal/hook"
)

const ownIBAN = "DE89370400440532013000"

func exfilCollector(t *testing.T) (*Collector, *memSink, *memSink) {
	t.Helper()
	c, events, traj := newTestCollector(t)
	c.cfg.MCPToolLabels = map[string]map[string][]string{
		"bank": {
			"get_iban":   {"sensitive", "read_only"},
			"read_file":  {"untrusted", "read_only"},
			"show":       {"read_only"},
			"send_money": {},
		},
	}
	return c, events, traj
}

func readIBAN(c *Collector, sid string) {
	c.Handle(mcpPost(sid, "mcp__bank__get_iban", map[string]any{}, "Your IBAN is "+ownIBAN))
}

func send(sid string, input map[string]any) *hook.Payload {
	return pre(sid, "p1", "mcp__bank__send_money", input)
}

// The case the class exists for: private data read by a sensitive tool leaves in the
// payload of an acting call.
func TestExfilEdgeOnPrivateDataInThePayload(t *testing.T) {
	c, events, traj := exfilCollector(t)
	readIBAN(c, "s1")
	src := last(t, traj)
	c.Handle(send("s1", map[string]any{"recipient": "GB29NWBK60161331926819", "amount": 1, "subject": "ref " + ownIBAN}))
	e := last(t, traj)
	if len(e.Provenance.Exfil) == 0 || e.Provenance.Exfil[0].MatchClass != "iban" {
		t.Fatalf("exfil = %+v, want an iban edge", e.Provenance.Exfil)
	}
	if e.Provenance.Exfil[0].FromEvent != src.EventID {
		t.Error("the edge does not point at the sensitive read")
	}
	if c.Stats().Provenance.ExfilEvents != 1 {
		t.Errorf("ExfilEvents = %d, want 1", c.Stats().Provenance.ExfilEvents)
	}
	// Spool only: the flattened event carries no exfil field until its precision is known.
	flat := events.decode(t, events.count()-1)
	for k := range flat {
		if len(k) >= 5 && k[:5] == "exfil" {
			t.Errorf("flattened event carries %s; exfil edges are spool-only", k)
		}
	}
}

// A private value used as the destination is the user addressing someone they know.
// AgentDojo shows that pattern equally in benign and hostile runs.
func TestNoExfilEdgeWhenThePrivateValueIsTheDestination(t *testing.T) {
	c, _, traj := exfilCollector(t)
	readIBAN(c, "s1")
	c.Handle(send("s1", map[string]any{"recipient": ownIBAN, "amount": 1, "subject": "savings"}))
	if got := last(t, traj).Provenance.Exfil; len(got) != 0 {
		t.Errorf("a private value in the recipient field drew an exfil edge: %+v", got)
	}
}

func TestOnlyActingCallsAreMatched(t *testing.T) {
	c, _, traj := exfilCollector(t)
	readIBAN(c, "s1")
	c.Handle(pre("s1", "p1", "mcp__bank__show", map[string]any{"text": ownIBAN}))
	if got := last(t, traj).Provenance.Exfil; len(got) != 0 {
		t.Errorf("a read-only call drew an exfil edge: %+v; nothing can leave through it", got)
	}
}

// A value the user typed is theirs to send.
func TestUserTypedValueIsNotExfil(t *testing.T) {
	c, _, traj := exfilCollector(t)
	c.Handle(prompt("s1", "send my IBAN "+ownIBAN+" to my accountant"))
	readIBAN(c, "s1")
	c.Handle(send("s1", map[string]any{"recipient": "GB29NWBK60161331926819", "subject": ownIBAN}))
	if got := last(t, traj).Provenance.Exfil; len(got) != 0 {
		t.Errorf("a value the user typed drew an exfil edge: %+v", got)
	}
}

// Untrusted content is provenance's business, not private data: it does not feed the
// sensitive set.
func TestUntrustedOnlyResultDoesNotFeedTheSensitiveSet(t *testing.T) {
	c, _, traj := exfilCollector(t)
	c.Handle(mcpPost("s1", "mcp__bank__read_file", map[string]any{"file_path": "bill.txt"}, "Pay to "+ownIBAN))
	c.Handle(send("s1", map[string]any{"recipient": "GB29NWBK60161331926819", "subject": ownIBAN}))
	e := last(t, traj)
	if len(e.Provenance.Exfil) != 0 {
		t.Errorf("an untrusted-only result fed the sensitive set: %+v", e.Provenance.Exfil)
	}
	if len(e.Provenance.Edges) == 0 {
		t.Error("test premise broken: the untrusted value should still draw a provenance edge")
	}
}

// A hostname is not private data. On AgentDojo, domain matches made up most of the benign
// sensitive-data edges and none of the useful ones: a channel summary naming the sites
// people had shared. The untrusted-content set still draws its edge from the same host.
func TestAHostnameInThePayloadIsNotExfil(t *testing.T) {
	c, _, traj := exfilCollector(t)
	c.cfg.MCPToolLabels["bank"]["get_notes"] = []string{"sensitive", "untrusted", "read_only"}
	c.Handle(mcpPost("s1", "mcp__bank__get_notes", map[string]any{}, "Bob shared www.shared-article.example in general."))
	c.Handle(send("s1", map[string]any{"recipient": "GB29NWBK60161331926819", "subject": "Summary: www.shared-article.example"}))
	e := last(t, traj)
	if len(e.Provenance.Exfil) != 0 {
		t.Errorf("a hostname drew an exfil edge: %+v", e.Provenance.Exfil)
	}
	if len(e.Provenance.Edges) == 0 {
		t.Error("test premise broken: the untrusted result should still draw a provenance edge on the host")
	}
}

func TestRenderPayloadDropsAddressingFields(t *testing.T) {
	p := &hook.Payload{ToolInput: map[string]any{
		"Recipients": []string{"a@x.test"}, "TO": "b@x.test", "url": "https://x.test", "file_path": "/tmp/x",
		"subject": "SUBJ", "body": "BODY",
	}}
	got := renderPayload(p)
	for _, keep := range []string{"SUBJ", "BODY"} {
		if !contains(got, keep) {
			t.Errorf("payload %q lost %q", got, keep)
		}
	}
	for _, drop := range []string{"a@x.test", "b@x.test", "https://x.test", "/tmp/x"} {
		if contains(got, drop) {
			t.Errorf("payload %q kept addressing value %q", got, drop)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
