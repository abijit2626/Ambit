package r2

import (
	"testing"

	"github.com/abijit2626/ambit/internal/event"
)

func TestClassifyTool_CredentialRead(t *testing.T) {
	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneCredential, Op: "read"}},
	})
	want := Bits{B: true}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestClassifyTool_CredentialWriteAlsoSetsC(t *testing.T) {

	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneCredential, Op: "write"}},
	})
	if !got.C {
		t.Errorf("got %+v, want C set: a credential-zone write is a write outside the working directory", got)
	}
}

func TestClassifyTool_UntrustedZoneRead(t *testing.T) {
	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneUntrusted, Op: "read"}},
	})
	if !got.A {
		t.Error("an untrusted-zone read should set bit A (ingest)")
	}
	if !got.B {
		t.Error("an untrusted-zone read is also outside the working directory, so bit B should be set too")
	}
}

func TestClassifyTool_WorkdirReadSetsNothing(t *testing.T) {
	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneWorkdir, Op: "read"}},
	})
	if got.Any() {
		t.Errorf("an ordinary workdir read should set no bit, got %+v", got)
	}
}

func TestClassifyTool_UnknownZoneReadSetsNothing(t *testing.T) {

	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneUnknown, Op: "read"}},
	})
	if got.Any() {
		t.Errorf("an unknown-zone read should set no bit, got %+v", got)
	}
}

func TestClassifyTool_HomeReadSetsB(t *testing.T) {

	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneHome, Op: "read"}},
	})
	if !got.B {
		t.Error("a home-zone read is outside the working directory and should set B")
	}
}

func TestClassifyTool_WriteOutsideWorkdirSetsC(t *testing.T) {
	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneSystem, Op: "write"}},
	})
	if !got.C {
		t.Error("a write outside the working directory should set C")
	}
	if got.B {
		t.Error("a write is not a read; B should not be set by this rule")
	}
}

func TestClassifyTool_WriteInsideWorkdirSetsNothing(t *testing.T) {
	got := ClassifyTool(ToolInput{
		Paths: []event.PathRef{{Zone: event.ZoneWorkdir, Op: "write"}},
	})
	if got.Any() {
		t.Errorf("an ordinary workdir write should set no bit, got %+v", got)
	}
}

func TestClassifyTool_SecretHitSetsB(t *testing.T) {
	got := ClassifyTool(ToolInput{SecretHitCount: 1})
	if !got.B {
		t.Error("a secret hit should set bit B regardless of path")
	}
}

func TestClassifyTool_NetworkBashSetsAAndC(t *testing.T) {
	got := ClassifyTool(ToolInput{Bash: &event.Bash{CommandClass: "network"}})
	if !got.A || !got.C {
		t.Errorf("a network-capable bash command should set both A and C, got %+v", got)
	}
}

func TestClassifyTool_VCSWriteAndPublishAreNetworkClass(t *testing.T) {
	for _, class := range []string{"vcs_write", "publish"} {
		got := ClassifyTool(ToolInput{Bash: &event.Bash{CommandClass: class}})
		if !got.A || !got.C {
			t.Errorf("class %q: got %+v, want both A and C", class, got)
		}
	}
}

func TestClassifyTool_ReadOnlyAndFilesystemBashSetNothing(t *testing.T) {
	for _, class := range []string{"read_only", "filesystem", "other"} {
		got := ClassifyTool(ToolInput{Bash: &event.Bash{CommandClass: class}})
		if got.Any() {
			t.Errorf("class %q should set no bit, got %+v", class, got)
		}
	}
}

func TestClassifyTool_NonInternalMCPSetsAAndC(t *testing.T) {
	got := ClassifyTool(ToolInput{MCP: &event.MCP{Server: "github", Trust: ""}})
	if !got.A || !got.C {
		t.Errorf("a non-internal MCP tool should set both A and C, got %+v", got)
	}
}

func TestClassifyTool_InternalMCPSetsNothing(t *testing.T) {
	got := ClassifyTool(ToolInput{MCP: &event.MCP{Server: "internal-wiki", Trust: "internal"}})
	if got.Any() {
		t.Errorf("an internal-trust MCP tool should set no bit, got %+v", got)
	}
}

func TestClassifyTool_MCPReadOnlyHintEarnsNoRelaxation(t *testing.T) {

	got := ClassifyTool(ToolInput{MCP: &event.MCP{Server: "external-docs", Trust: ""}})
	if !got.A || !got.C {
		t.Error("trust alone should decide this; a claimed hint (not modeled here) must not relax it")
	}
}

func TestClassifyTool_WebUntrustedSetsA(t *testing.T) {
	for _, tool := range []string{"WebFetch", "WebSearch"} {
		got := ClassifyTool(ToolInput{ToolName: tool, WebUntrusted: true})
		if !got.A {
			t.Errorf("%s with WebUntrusted should set A", tool)
		}
		if got.C {
			t.Errorf("%s alone should not set C", tool)
		}
	}
}

func TestClassifyTool_WebTrustedSetsNothing(t *testing.T) {
	got := ClassifyTool(ToolInput{ToolName: "WebFetch", WebUntrusted: false})
	if got.Any() {
		t.Errorf("a trusted-domain WebFetch should set no bit, got %+v", got)
	}
}

func TestClassifyTool_WebUntrustedIgnoredForNonWebTools(t *testing.T) {

	got := ClassifyTool(ToolInput{ToolName: "Read", WebUntrusted: true})
	if got.Any() {
		t.Errorf("WebUntrusted on a non-web tool should set no bit, got %+v", got)
	}
}

func TestClassifyTool_MultiplePathsOR(t *testing.T) {

	got := ClassifyTool(ToolInput{Paths: []event.PathRef{
		{Zone: event.ZoneWorkdir, Op: "read"},
		{Zone: event.ZoneCredential, Op: "read"},
	}})
	if !got.B {
		t.Error("the credential path among several should still set B")
	}
}

func TestClassifyInstructionsLoaded(t *testing.T) {
	if got := ClassifyInstructionsLoaded(true); got.Any() {
		t.Errorf("a trusted-repo instruction file should set no bit, got %+v", got)
	}
	got := ClassifyInstructionsLoaded(false)
	if !got.A || got.B || got.C {
		t.Errorf("an untrusted-repo instruction file should set only A, got %+v", got)
	}
}

func TestBits_Or(t *testing.T) {
	a := Bits{A: true}
	b := Bits{B: true, C: true}
	got := a.Or(b)
	want := Bits{A: true, B: true, C: true}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestBits_Any(t *testing.T) {
	if (Bits{}).Any() {
		t.Error("zero-value Bits should report Any() == false")
	}
	if !(Bits{C: true}).Any() {
		t.Error("a single set bit should report Any() == true")
	}
}

func classified(trust string, labels ...string) *event.MCP {
	return &event.MCP{Server: "bank", Tool: "t", Trust: trust, Classified: true, Labels: labels}
}

func TestClassifiedMCPToolBitsComeFromLabels(t *testing.T) {
	cases := []struct {
		name string
		mcp  *event.MCP
		want Bits
	}{
		{"untrusted read", classified("", "untrusted", "read_only"), Bits{A: true}},
		{"sensitive read", classified("", "sensitive", "read_only"), Bits{B: true}},
		{"untrusted sensitive read", classified("", "sensitive", "untrusted", "read_only"), Bits{A: true, B: true}},
		{"write with no labels", classified(""), Bits{C: true}},
		{"plain read", classified("", "read_only"), Bits{}},

		{"sensitive read on an internal server", classified("internal", "sensitive", "read_only"), Bits{B: true}},
	}
	for _, c := range cases {
		if got := ClassifyTool(ToolInput{ToolName: "mcp__bank__t", MCP: c.mcp}); got != c.want {
			t.Errorf("%s: bits = %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestUnclassifiedMCPToolKeepsTheDefault(t *testing.T) {
	if got := ClassifyTool(ToolInput{MCP: &event.MCP{Server: "x", Tool: "y"}}); got != (Bits{A: true, C: true}) {
		t.Errorf("unclassified, untrusted server = %+v, want A and C", got)
	}
	if got := ClassifyTool(ToolInput{MCP: &event.MCP{Server: "x", Tool: "y", Trust: "internal"}}); got.Any() {
		t.Errorf("unclassified, internal server = %+v, want nothing", got)
	}
}
