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

		{"/home/dev/.ssh/id_ed25519", event.ZoneCredential, "ssh private key"},
		{"/home/dev/.aws/credentials", event.ZoneCredential, "aws credentials"},
		{"/home/dev/src/myrepo/.env", event.ZoneCredential, "dotenv in the working directory is still a credential"},
		{"/home/dev/src/myrepo/.env.production", event.ZoneCredential, "suffixed dotenv"},
		{"/home/dev/src/myrepo/config/prod.env", event.ZoneCredential, "trailing .env"},
		{"/home/dev/.npmrc", event.ZoneCredential, "npm token file"},
		{"/home/dev/src/myrepo/certs/server.pem", event.ZoneCredential, "cert material by extension"},
		{"/home/dev/.config/gcloud/application_default_credentials.json", event.ZoneCredential, "gcloud adc"},
		{"/home/dev/.kube/config", event.ZoneCredential, "kubeconfig holds tokens"},

		{"/home/dev/src/myrepo/node_modules/evil/.env", event.ZoneCredential, "dotenv inside a dependency tree is still credential"},
		{"/home/dev/src/myrepo/node_modules/pkg/key.pem", event.ZoneCredential, "key inside a dependency tree"},

		{"/home/dev/.ssh/id_ed25519.pub", event.ZoneHome, "public key is not a secret"},
		{"/home/dev/.ssh/known_hosts", event.ZoneHome, "known_hosts is not a secret"},
		{"/home/dev/.ssh/config", event.ZoneHome, "ssh config is not a secret"},

		{"/etc/passwd", event.ZoneSystem, "system tree"},
		{"/usr/lib/libc.so", event.ZoneSystem, "system tree"},
		{"/System/Library/Frameworks/Foo", event.ZoneSystem, "macOS system tree"},

		{"/home/dev/src/myrepo/node_modules/left-pad/index.js", event.ZoneUntrusted, "dependency source"},
		{"/home/dev/src/myrepo/vendor/github.com/x/y.go", event.ZoneUntrusted, "vendored source"},
		{"/home/dev/go/pkg/mod/example.com/z@v1/f.go", event.ZoneUntrusted, "module cache"},
		{"/home/dev/Downloads/installer.sh", event.ZoneUntrusted, "downloads"},
		{"/opt/thirdparty/blob.js", event.ZoneUntrusted, "operator-configured untrusted fragment"},

		{"/home/dev/src/myrepo/main.go", event.ZoneWorkdir, "ordinary source file"},
		{"/home/dev/src/myrepo/deep/nested/file.ts", event.ZoneWorkdir, "nested source file"},
		{"/home/dev/notes.txt", event.ZoneHome, "home but not workdir"},
		{"/home/dev/src/other/main.go", event.ZoneHome, "different repo under home"},

		{"/tmp/scratch", event.ZoneUnknown, "neither home nor workdir nor system"},
		{"", event.ZoneUnknown, "empty path"},
	}

	for _, c := range cases {
		if got := z.Zone(c.path); got != c.want {
			t.Errorf("Zone(%q) = %q, want %q (%s)", c.path, got, c.want, c.why)
		}
	}
}

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

func TestZoneWindowsPaths(t *testing.T) {
	z := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, nil)
	cases := []struct {
		path string
		want string
		why  string
	}{

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

		{`C:\Users\dev\.ssh\id_ed25519.pub`, event.ZoneHome, "public key"},
		{`C:\Users\dev\.ssh\config`, event.ZoneHome, "ssh config"},

		{`C:\Windows\System32\drivers\etc\hosts`, event.ZoneSystem, "windows tree"},
		{`C:\Program Files\Git\bin\git.exe`, event.ZoneSystem, "program files"},
		{`C:\Program Files (x86)\Foo\foo.dll`, event.ZoneSystem, "program files (x86)"},
		{`d:\windows\notepad.exe`, event.ZoneSystem, "any drive letter"},

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

		{"/c/projects/x.go", event.ZoneUnknown},

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

func TestZoneWindowsNameCanonicalization(t *testing.T) {
	z := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, nil)
	for _, p := range []string{
		`C:\Users\dev\src\myrepo\.npmrc.`,
		`C:\Users\dev\src\myrepo\.npmrc `,
		`C:\Users\dev\src\myrepo\.npmrc...`,
		`C:\Users\dev\src\myrepo\key.pem.`,
		`C:\Users\dev\src\myrepo\key.pem::$DATA`,
		`C:\Users\dev\src\myrepo\.npmrc::$DATA`,
		`C:\Users\dev\.aws\credentials:Zone.Identifier`,
		`C:\Users\dev\.aws.\credentials`,
		`C:\Users\dev\.ssh\id_rsa.`,
		`C:\Users\dev\src\myrepo\.netrc.`,
		`C:\Users\dev\src\myrepo\cert.pfx::$DATA`,
		`/mnt/c/Users/dev/src/myrepo/.npmrc.`,
	} {
		if got := z.Zone(p); got != event.ZoneCredential {
			t.Errorf("Zone(%q) = %q, want credential", p, got)
		}
	}

	for _, p := range []string{
		`C:\Users\dev\src\myrepo\main.go.`,
		`C:\Users\dev\src\myrepo\notes.txt:stream`,
	} {
		if got := z.Zone(p); got != event.ZoneWorkdir {
			t.Errorf("Zone(%q) = %q, want workdir", p, got)
		}
	}
}

func TestZoneWindowsDriveRootIsACeiling(t *testing.T) {
	z := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, nil)
	cases := []struct {
		path string
		want string
	}{
		{`C:\Users\dev\..\..\..\Windows\win.ini`, event.ZoneSystem},
		{`C:\..\Windows\System32\config\SAM`, event.ZoneCredential},
		{`C:\Users\dev\src\myrepo\..\..\..\..\..\ProgramData\x`, event.ZoneUnknown},
		{`C:\Users\dev\src\myrepo\..\..\.ssh\id_rsa`, event.ZoneCredential},
	}
	for _, c := range cases {
		if got := z.Zone(c.path); got != c.want {
			t.Errorf("Zone(%q) = %q, want %q", c.path, got, c.want)
		}
	}
	for in, want := range map[string]string{
		`C:\Users\dev\..\..\..\Windows\win.ini`: "C:/Windows/win.ini",
		`C:\..\..`:                              "C:/",
		`\\?\UNC\server\share\x`:                "//server/share/x",
		`\\?\UNC\server\share\..\..\x`:          "//server/share/x",
		`\\server\share\a\..\b`:                 "//server/share/b",
		`\\.\C:\Users\dev`:                      "C:/Users/dev",
		`C:\Users\dev\src\myrepo\..\..\..\..\..\..\ProgramData\x`: "C:/ProgramData/x",
	} {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestZoneLeadingDoubleSlash(t *testing.T) {
	old := hostIsWindows
	defer func() { hostIsWindows = old }()

	hostIsWindows = false
	z := NewZoner("/home/dev", "/home/dev/src/myrepo", nil)
	for p, want := range map[string]string{
		"//home/dev/notes.txt":           event.ZoneHome,
		"//home/dev/src/myrepo/main.go":  event.ZoneWorkdir,
		"//home/dev/.ssh/id_rsa":         event.ZoneCredential,
		"///home/dev/notes.txt":          event.ZoneHome,
		"//etc/passwd":                   event.ZoneSystem,
		`\\fileserver\share\.ssh\id_rsa`: event.ZoneCredential,
	} {
		if got := z.Zone(p); got != want {
			t.Errorf("unix host: Zone(%q) = %q, want %q", p, got, want)
		}
	}
	if got := normalize("//home/dev/x"); got != "/home/dev/x" {
		t.Errorf("unix host: normalize(//home/dev/x) = %q, want /home/dev/x", got)
	}
	if got := normalize(`\\server\share\x`); got != "//server/share/x" {
		t.Errorf("unix host: normalize of a backslash UNC path = %q, want it kept as UNC", got)
	}

	hostIsWindows = true
	if got := normalize("//server/share/x"); got != "//server/share/x" {
		t.Errorf("windows host: normalize(//server/share/x) = %q, want it kept as UNC", got)
	}
}

func TestZoneSystemFragmentsDoNotSwallowProjectDirectories(t *testing.T) {
	z := NewZoner("/Users/dev", "/Users/dev/src/myrepo", nil)
	for p, want := range map[string]string{
		"/Users/dev/src/myrepo/bin/Debug/net8.0/app.dll": event.ZoneWorkdir,
		"/Users/dev/src/myrepo/system/a.go":              event.ZoneWorkdir,
		"/Users/dev/src/myrepo/Library/Bee/x":            event.ZoneWorkdir,
		"/Users/dev/Library/Application Support/x":       event.ZoneHome,
		"/Users/dev/.local/bin/tool":                     event.ZoneHome,
		"/Users/dev/src/myrepo/node_modules/x/bin/y.js":  event.ZoneUntrusted,
		"/usr/local/bin/tool":                            event.ZoneSystem,
		"/Library/Preferences/x.plist":                   event.ZoneSystem,
		"/mnt/rootfs/etc/hosts":                          event.ZoneSystem,
	} {
		if got := z.Zone(p); got != want {
			t.Errorf("Zone(%q) = %q, want %q", p, got, want)
		}
	}

	w := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, nil)
	for p, want := range map[string]string{
		`C:\Users\dev\src\myrepo\bin\Debug\app.dll`: event.ZoneWorkdir,
		`C:\Users\dev\src\myrepo\system\a.go`:       event.ZoneWorkdir,
		`C:\PROGRA~1\Git\bin\git.exe`:               event.ZoneSystem,
	} {
		if got := w.Zone(p); got != want {
			t.Errorf("Zone(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestZoneExtraUntrustedAcceptsBackslashes(t *testing.T) {
	z := NewZoner(`C:\Users\dev`, `C:\Users\dev\src\myrepo`, []string{`C:\Users\dev\thirdparty`, `\vendor-code\`})
	for _, p := range []string{
		`C:\Users\dev\thirdparty\lib\a.go`,
		`C:\Users\dev\src\myrepo\vendor-code\x.go`,
		`C:/Users/dev/thirdparty/lib/a.go`,
	} {
		if got := z.Zone(p); got != event.ZoneUntrusted {
			t.Errorf("Zone(%q) = %q, want untrusted", p, got)
		}
	}
}
