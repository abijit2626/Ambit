package classify

import (
	"testing"

	"github.com/abijit2626/indirect-prompt/internal/event"
)

func testZoner() *Zoner {
	return NewZoner("/home/dev", "/home/dev/src/myrepo", []string{"/opt/thirdparty/"})
}

func TestZone(t *testing.T) {
	z := testZoner()
	cases := []struct {
		path string
		want string
		why  string
	}{
		// Credential, wherever it lives.
		{"/home/dev/.ssh/id_ed25519", event.ZoneCredential, "ssh private key"},
		{"/home/dev/.aws/credentials", event.ZoneCredential, "aws credentials"},
		{"/home/dev/src/myrepo/.env", event.ZoneCredential, "dotenv in the working directory is still a credential"},
		{"/home/dev/src/myrepo/.env.production", event.ZoneCredential, "suffixed dotenv"},
		{"/home/dev/src/myrepo/config/prod.env", event.ZoneCredential, "trailing .env"},
		{"/home/dev/.npmrc", event.ZoneCredential, "npm token file"},
		{"/home/dev/src/myrepo/certs/server.pem", event.ZoneCredential, "cert material by extension"},
		{"/home/dev/.config/gcloud/application_default_credentials.json", event.ZoneCredential, "gcloud adc"},
		{"/home/dev/.kube/config", event.ZoneCredential, "kubeconfig holds tokens"},

		// The precedence rule that matters most: credential must outrank
		// untrusted, or the highest-severity signal hides behind a lower one.
		{"/home/dev/src/myrepo/node_modules/evil/.env", event.ZoneCredential, "dotenv inside a dependency tree is still credential"},
		{"/home/dev/src/myrepo/node_modules/pkg/key.pem", event.ZoneCredential, "key inside a dependency tree"},

		// Not credentials, and flagging them would add noise.
		{"/home/dev/.ssh/id_ed25519.pub", event.ZoneHome, "public key is not a secret"},
		{"/home/dev/.ssh/known_hosts", event.ZoneHome, "known_hosts is not a secret"},
		{"/home/dev/.ssh/config", event.ZoneHome, "ssh config is not a secret"},

		// System.
		{"/etc/passwd", event.ZoneSystem, "system tree"},
		{"/usr/lib/libc.so", event.ZoneSystem, "system tree"},
		{"/System/Library/Frameworks/Foo", event.ZoneSystem, "macOS system tree"},

		// Untrusted.
		{"/home/dev/src/myrepo/node_modules/left-pad/index.js", event.ZoneUntrusted, "dependency source"},
		{"/home/dev/src/myrepo/vendor/github.com/x/y.go", event.ZoneUntrusted, "vendored source"},
		{"/home/dev/go/pkg/mod/example.com/z@v1/f.go", event.ZoneUntrusted, "module cache"},
		{"/home/dev/Downloads/installer.sh", event.ZoneUntrusted, "downloads"},
		{"/opt/thirdparty/blob.js", event.ZoneUntrusted, "operator-configured untrusted fragment"},

		// Workdir and home.
		{"/home/dev/src/myrepo/main.go", event.ZoneWorkdir, "ordinary source file"},
		{"/home/dev/src/myrepo/deep/nested/file.ts", event.ZoneWorkdir, "nested source file"},
		{"/home/dev/notes.txt", event.ZoneHome, "home but not workdir"},
		{"/home/dev/src/other/main.go", event.ZoneHome, "different repo under home"},

		// Outside everything.
		{"/tmp/scratch", event.ZoneUnknown, "neither home nor workdir nor system"},
		{"", event.ZoneUnknown, "empty path"},
	}

	for _, c := range cases {
		if got := z.Zone(c.path); got != c.want {
			t.Errorf("Zone(%q) = %q, want %q (%s)", c.path, got, c.want, c.why)
		}
	}
}

// TestZoneWorkdirBoundaryIsSegmentWise guards against a prefix-match bug where
// a sibling directory sharing a name prefix is read as being inside the
// working directory.
func TestZoneWorkdirBoundaryIsSegmentWise(t *testing.T) {
	z := NewZoner("/home/dev", "/home/dev/src/repo", nil)
	if got := z.Zone("/home/dev/src/repo-other/main.go"); got == event.ZoneWorkdir {
		t.Error("repo-other must not classify as workdir: prefix matching would be a scoping bug")
	}
	if got := z.Zone("/home/dev/src/repo/main.go"); got != event.ZoneWorkdir {
		t.Errorf("Zone(repo/main.go) = %q, want workdir", got)
	}
}

func TestZoneNormalizesTraversalAndSeparators(t *testing.T) {
	z := testZoner()
	// A traversal that resolves into the credential zone must be caught after
	// cleaning, not evaluated as written.
	if got := z.Zone("/home/dev/src/myrepo/../../.ssh/id_rsa"); got != event.ZoneCredential {
		t.Errorf("traversal into .ssh = %q, want credential", got)
	}
	if got := z.Zone(`C:\Users\dev\.ssh\id_rsa`); got != event.ZoneCredential {
		t.Errorf("windows-separator path = %q, want credential", got)
	}
}

func TestHighestZone(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{event.ZoneWorkdir, event.ZoneCredential, event.ZoneUntrusted}, event.ZoneCredential},
		{[]string{event.ZoneWorkdir, event.ZoneUntrusted}, event.ZoneUntrusted},
		{[]string{event.ZoneWorkdir, event.ZoneHome}, event.ZoneHome},
		{[]string{event.ZoneSystem, event.ZoneUntrusted}, event.ZoneSystem},
		{nil, event.ZoneUnknown},
	}
	for _, c := range cases {
		if got := HighestZone(c.in); got != c.want {
			t.Errorf("HighestZone(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
