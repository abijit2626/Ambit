package classify

import (
	"testing"

	"github.com/abijit2626/ambit/internal/event"
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

// The Windows cases run on every host: normalize turns the path into one form before
// anything is compared, so a Linux CI run exercises exactly what a Windows endpoint
// will see.
func TestZoneWindowsPaths(t *testing.T) {
	z := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, nil)
	cases := []struct {
		path string
		want string
		why  string
	}{
		// Credential.
		{`C:\Users\dev\.ssh\id_ed25519`, event.ZoneCredential, "ssh private key"},
		{`C:\Users\dev\.aws\credentials`, event.ZoneCredential, "aws credentials"},
		{`c:\users\DEV\.AWS\Credentials`, event.ZoneCredential, "case does not matter on Windows"},
		{`C:\Users\dev\src\myrepo\.env`, event.ZoneCredential, "dotenv in the working directory"},
		{`C:\Users\dev\AppData\Roaming\gcloud\credentials.db`, event.ZoneCredential, "gcloud lives under AppData on Windows"},
		{`C:\Users\dev\AppData\Roaming\GitHub CLI\hosts.yml`, event.ZoneCredential, "gh token file"},
		{`C:\Users\dev\AppData\Roaming\Microsoft\Credentials\ABCDEF`, event.ZoneCredential, "DPAPI credential blob"},
		{`C:\Users\dev\AppData\Roaming\Microsoft\Protect\S-1-5-21-1\key`, event.ZoneCredential, "DPAPI master key"},
		{`C:\Windows\System32\config\SAM`, event.ZoneCredential, "credential outranks system"},
		{`C:\Users\dev\src\myrepo\node_modules\evil\.env`, event.ZoneCredential, "credential outranks untrusted"},
		{`\\?\C:\Users\dev\.ssh\id_rsa`, event.ZoneCredential, "extended-length prefix names the same file"},
		{`C:\Users\dev\src\myrepo\..\..\.ssh\id_rsa`, event.ZoneCredential, "backslash traversal is cleaned, not evaluated as written"},

		// Not credentials.
		{`C:\Users\dev\.ssh\id_ed25519.pub`, event.ZoneHome, "public key"},
		{`C:\Users\dev\.ssh\config`, event.ZoneHome, "ssh config"},

		// System.
		{`C:\Windows\System32\drivers\etc\hosts`, event.ZoneSystem, "windows tree"},
		{`C:\Program Files\Git\bin\git.exe`, event.ZoneSystem, "program files"},
		{`C:\Program Files (x86)\Foo\foo.dll`, event.ZoneSystem, "program files (x86)"},
		{`d:\windows\notepad.exe`, event.ZoneSystem, "any drive letter"},

		// Untrusted, workdir, home.
		{`C:\Users\dev\src\myrepo\node_modules\pkg\index.js`, event.ZoneUntrusted, "dependency tree"},
		{`C:\Users\dev\Downloads\setup.exe`, event.ZoneUntrusted, "downloads"},
		{`C:\Users\dev\src\myrepo\main.go`, event.ZoneWorkdir, "inside the working directory"},
		{`C:\USERS\DEV\SRC\MYREPO\main.go`, event.ZoneWorkdir, "working directory, different case"},
		{`C:\Users\dev\notes.txt`, event.ZoneHome, "inside home"},
		{`C:\Users\devx\notes.txt`, event.ZoneUnknown, "devx is not under dev: segments are compared, not prefixes"},
		{`C:\ProgramData\ambit\events.jsonl`, event.ZoneUnknown, "ProgramData is data, not system"},
		{`C:\Users\dev\src\windows\main.go`, event.ZoneHome, "a project directory called windows is not the OS"},
	}
	for _, c := range cases {
		if got := z.Zone(c.path); got != c.want {
			t.Errorf("Zone(%q) = %q, want %q (%s)", c.path, got, c.want, c.why)
		}
	}
}

// WSL and Git Bash spell the same Windows paths differently. Claude Code can report
// either, and the zone must not depend on which shell the developer happened to use.
func TestZoneWindowsPathsFromWSLAndGitBash(t *testing.T) {
	z := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, nil)
	cases := []struct {
		path string
		want string
	}{
		{"/mnt/c/Users/dev/.ssh/id_rsa", event.ZoneCredential},
		{"/mnt/c/Windows/System32/cmd.exe", event.ZoneSystem},
		{"/mnt/c/Users/dev/src/myrepo/main.go", event.ZoneWorkdir},
		{"/c/Users/dev/.aws/credentials", event.ZoneCredential},
		{"/c/Users/dev/src/myrepo/main.go", event.ZoneWorkdir},
		{"/C/Program Files/Git/bin/git.exe", event.ZoneSystem},
		// A single-letter directory that is not a Windows root is not a drive.
		{"/c/projects/x.go", event.ZoneUnknown},
		// The UNC form is kept distinct from a plain rooted path.
		{`\\fileserver\share\.ssh\id_rsa`, event.ZoneCredential},
	}
	for _, c := range cases {
		if got := z.Zone(c.path); got != c.want {
			t.Errorf("Zone(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"/home/dev/a/../b":     "/home/dev/b",
		`C:\Users\dev\a\..\b`:  "C:/Users/dev/b",
		`\\?\C:\Users\dev`:     "C:/Users/dev",
		`\\fileserver\share\x`: "//fileserver/share/x",
		"/mnt/c/Users/dev":     "C:/Users/dev",
		"/mnt/d":               "D:/",
		"/c/Users/dev":         "C:/Users/dev",
		"/c/projects":          "/c/projects",
		"/mnt/cache/x":         "/mnt/cache/x",
		`C:\`:                  "C:/",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
