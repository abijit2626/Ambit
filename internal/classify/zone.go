// Package classify assigns zone labels to filesystem paths and command classes
// to shell commands.
//
// Zone labels are the one piece of path information that crosses to Wazuh in
// cleartext, because the zone carries the security meaning while the path
// carries our source-tree layout. An external analyst who cannot resolve a
// digest can still act on "a credential-zone read preceded egress". See
// docs/01-threat-model.md on the MSSP posture.
package classify

import (
	"path"
	"regexp"
	"runtime"
	"strings"

	"github.com/abijit2626/ambit/internal/event"
)

// Zoner classifies paths relative to a session's working directory and the
// user's home.
type Zoner struct {
	home    string
	workdir string
	// extraUntrusted holds operator-configured untrusted path fragments.
	extraUntrusted []string
}

func NewZoner(home, workdir string, extraUntrusted []string) *Zoner {
	// Paths are compared with forward slashes, so a fragment an operator wrote with
	// backslashes (`C:\Users\dev\thirdparty`, `\vendor-code\`) has to be spelled the same
	// way or it can never match.
	frags := make([]string, len(extraUntrusted))
	for i, f := range extraUntrusted {
		frags[i] = strings.ReplaceAll(f, `\`, "/")
	}
	return &Zoner{
		home:           normalize(home),
		workdir:        normalize(workdir),
		extraUntrusted: frags,
	}
}

// credentialBasenames are filenames that are credential-bearing wherever they
// appear, including inside a working directory or a dependency tree.
var credentialBasenames = map[string]bool{
	".npmrc":           true,
	".netrc":           true,
	".pgpass":          true,
	".git-credentials": true,
	"credentials":      true, // ~/.aws/credentials and friends
	".htpasswd":        true,
	"id_rsa":           true,
	"id_dsa":           true,
	"id_ecdsa":         true,
	"id_ed25519":       true,
}

// credentialExts are extensions that indicate key or certificate material.
var credentialExts = map[string]bool{
	".pem":      true,
	".key":      true,
	".p12":      true,
	".pfx":      true,
	".jks":      true,
	".keystore": true,
	".kdbx":     true,
}

// credentialDirs maps directory fragments whose contents are credential-bearing
// to the basenames within them that are NOT secret.
//
// The exclusions are per-directory on purpose. "config" is not a secret in
// ~/.ssh — it is read constantly during ordinary git work and flagging it would
// add noise to the highest-severity zone — but ~/.kube/config IS the credential.
// A single shared exclusion list gets that backwards and hides the signal.
//
// Where a file's sensitivity is arguable, it stays credential. A false
// credential label costs noise; a missed one hides the signal the whole system
// exists to surface.
var credentialDirs = map[string][]string{
	"/.ssh/":           {"config", "known_hosts", "known_hosts.old", "authorized_keys"},
	"/.aws/":           nil,
	"/.gnupg/":         nil,
	"/.config/gcloud/": nil,
	"/.azure/":         nil,
	"/.kube/":          nil, // config is the credential here
	"/.docker/":        nil,
	"/.config/gh/":     nil,

	// Windows. The dot-directories above are the same under %USERPROFILE%; these are
	// the places Windows keeps what macOS and Linux keep in a keychain or in
	// ~/.config. Keys are lower case because Zone compares against a lower-cased
	// path, and Windows paths are case-insensitive.
	"/appdata/roaming/gcloud/":                nil,
	"/appdata/roaming/github cli/":            nil,
	"/appdata/roaming/microsoft/credentials/": nil, // DPAPI-protected credential blobs
	"/appdata/local/microsoft/credentials/":   nil,
	"/appdata/roaming/microsoft/protect/":     nil, // DPAPI master keys
	"/appdata/roaming/microsoft/crypto/":      nil, // CNG/CryptoAPI private keys
	"/windows/system32/config/":               nil, // SAM, SECURITY and SYSTEM hives
}

// untrustedDirs are directory fragments holding content we did not author.
// Reading here sets Rule-of-Two bit A.
var untrustedDirs = []string{
	"/node_modules/",
	"/vendor/",
	"/.venv/",
	"/site-packages/",
	"/bower_components/",
	"/.cargo/registry/",
	"/go/pkg/mod/",
	"/downloads/",
	"/.gradle/caches/",
	"/.m2/repository/",
}

// systemPrefixes are OS-owned trees. Zone matches them at the start of a path, and, only
// for a path that is under neither the working directory nor home, anywhere in it (a
// root file system mounted under another path, a chroot).
var systemPrefixes = []string{
	"/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/proc/", "/sys/",
	"/System/", "/Library/", "/private/etc/",
}

// windowsSystem matches the OS-owned trees on a Windows drive, against a
// lower-cased, forward-slashed path. It is anchored to a drive letter on purpose:
// "windows" as a bare fragment would label a project directory that happens to be
// called windows as system. ProgramData is left out for the same reason /var is
// not in systemPrefixes: it is where programs keep data, not where the OS lives.
// PROGRA~1 and PROGRA~2 are the 8.3 names of the two Program Files directories.
var windowsSystem = regexp.MustCompile(`^[a-z]:/(windows|program files|program files \(x86\)|progra~[12])(/|$)`)

// windowsDrive recognizes a path that begins with a drive letter, after
// normalize. Comparison rules for these are case-insensitive.
var windowsDrive = regexp.MustCompile(`^[A-Za-z]:/`)

// wslMount is how WSL exposes a Windows drive: /mnt/c/Users/dev.
var wslMount = regexp.MustCompile(`^/mnt/([A-Za-z])(/|$)`)

// bashDrive is how Git Bash and Cygwin expose a Windows drive: /c/Users/dev. A
// single-letter top-level directory is legal on Unix, so this only converts when the
// next segment is a well-known Windows root. Anything else is left alone rather than
// guessed at.
var bashDrive = regexp.MustCompile(`(?i)^/([a-z])/(users|windows|program files|program files \(x86\)|programdata)(/|$)`)

// Zone returns the zone label for a path.
//
// Precedence is deliberate and not merely a match order: credential outranks
// everything, so a .env inside node_modules is a credential read rather than a
// dependency read, and a .env in the working directory does not get downgraded
// to workdir. Getting this backwards would let the highest-severity signal in
// the system hide behind a lower-severity label.
func (z *Zoner) Zone(p0 string) string {
	if p0 == "" {
		return event.ZoneUnknown
	}
	p := normalize(p0)
	lower := strings.ToLower(p)
	base := strings.ToLower(path.Base(p))

	if isCredential(lower, base) {
		return event.ZoneCredential
	}
	if hasAnyPrefix(p, systemPrefixes) || windowsSystem.MatchString(lower) {
		return event.ZoneSystem
	}
	if hasAnyFragment(lower, untrustedDirs) || z.isExtraUntrusted(lower) {
		return event.ZoneUntrusted
	}
	if z.workdir != "" && isUnder(p, z.workdir) {
		return event.ZoneWorkdir
	}
	if z.home != "" && isUnder(p, z.home) {
		return event.ZoneHome
	}
	// A system directory name deeper in a path that is not ours: /mnt/rootfs/etc/hosts.
	// This comes after workdir and home on purpose. bin/, system/ and Library/ are
	// ordinary directories inside a project (bin/Debug in every .NET tree, Library/ in a
	// Unity one) or under a home directory (~/.local/bin, ~/Library on macOS), and
	// calling those system would cross every build-output read as a severe zone.
	if hasAnyFragment(lower, systemPrefixes) {
		return event.ZoneSystem
	}
	return event.ZoneUnknown
}

func isCredential(lowerPath, base string) bool {
	// Dotenv in any form: .env, .env.local, .env.production
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	if credentialBasenames[base] {
		return true
	}
	if credentialExts[strings.ToLower(path.Ext(base))] {
		return true
	}
	// id_* private keys, but not id_rsa.pub — a public key is not a secret and
	// flagging it would add noise to the highest-severity zone.
	if strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") {
		return true
	}
	for dir, nonSecret := range credentialDirs {
		if !strings.Contains(lowerPath, dir) {
			continue
		}
		// A public key is never a secret, in any credential directory.
		if strings.HasSuffix(base, ".pub") {
			return false
		}
		for _, ns := range nonSecret {
			if base == ns {
				return false
			}
		}
		return true
	}
	return false
}

func (z *Zoner) isExtraUntrusted(lowerPath string) bool {
	for _, frag := range z.extraUntrusted {
		if frag != "" && strings.Contains(lowerPath, strings.ToLower(frag)) {
			return true
		}
	}
	return false
}

func hasAnyFragment(lowerPath string, fragments []string) bool {
	for _, f := range fragments {
		if strings.Contains(lowerPath, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// isUnder reports whether p is within dir, comparing path segments so that
// /home/userx is not treated as being under /home/user.
func isUnder(p, dir string) bool {
	// Windows paths are case-insensitive. Fold both sides when either names a drive,
	// so C:/Users/Dev and c:/users/dev are the same directory.
	if windowsDrive.MatchString(p) || windowsDrive.MatchString(dir) {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	if p == dir {
		return true
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return strings.HasPrefix(p, dir)
}

// hostIsWindows decides how a leading // is read. On Windows it starts a UNC path
// (//server/share). On Unix it is the root: POSIX leaves it implementation-defined and
// Linux and macOS treat //home/user as /home/user, so it must reach the same zone as
// /home/user and not escape the workdir and home checks by being spelled differently.
// A leading \\ is a UNC path on every host, because only Windows writes it. A variable
// so a test can exercise both readings.
var hostIsWindows = runtime.GOOS == "windows"

// nativeDrive is a path that begins with a drive letter, before any conversion.
var nativeDrive = regexp.MustCompile(`^[A-Za-z]:(/|$)`)

// normalize puts a path in one comparable form: forward slashes, cleaned, with
// Windows drive paths spelled X:/... whichever way they arrived.
//
// Separators are converted before cleaning rather than after. filepath.Clean only
// understands the host's separator, so on Linux `a\..\b` would survive uncleaned
// and a traversal written with backslashes could name a credential path that the
// zone check never saw. path.Clean works on forward slashes and behaves the same on
// every host, which is what lets the Windows cases be tested on Linux CI.
//
// A drive or UNC root is split off before cleaning. path.Clean knows nothing about
// either, so left in, `C:` is an ordinary directory that `..` can climb out of, and
// C:\Users\dev\..\..\..\Windows becomes the relative Windows/... when Windows
// resolves it to C:\Windows.
//
// On Windows paths, the names below the root are also reduced to what Win32 opens:
// trailing dots and spaces are dropped from each name, and so is an NTFS stream suffix
// (:stream, ::$DATA). `.npmrc.`, `.npmrc ` and `key.pem::$DATA` are the files `.npmrc`
// and `key.pem`, and have to zone like them. 8.3 short names (CREDEN~1) cannot be
// expanded without the file system and are not.
func normalize(p string) string {
	if p == "" {
		return ""
	}
	backslashRoot := p[0] == '\\'
	p = strings.ReplaceAll(p, `\`, "/")

	unc := false
	// Extended-length (\\?\C:\...) and device (\\.\C:\...) prefixes name the same file as
	// the plain path, and \\?\UNC\server\share is the extended-length form of a UNC path.
	if strings.HasPrefix(p, "//?/") || strings.HasPrefix(p, "//./") {
		p = p[4:]
		if len(p) >= 4 && strings.EqualFold(p[:4], "UNC/") {
			p, unc = "//"+p[4:], true
		}
	} else if strings.HasPrefix(p, "//") && (backslashRoot || hostIsWindows) {
		unc = true
	}

	switch {
	case unc:
		host, after, _ := strings.Cut(strings.TrimLeft(p, "/"), "/")
		share, rest, _ := strings.Cut(after, "/")
		root := "//" + host
		if share != "" {
			root += "/" + share
		}
		return root + cleanBelowRoot(rest)
	case nativeDrive.MatchString(p):
		return strings.ToUpper(p[:1]) + ":" + cleanBelowRoot(p[2:]) + driveRootSlash(p[2:])
	}

	p = path.Clean(p)
	if m := wslMount.FindStringSubmatch(p); m != nil {
		d := strings.ToUpper(m[1]) + ":"
		rest := p[len(m[0])-len(m[2]):]
		return d + cleanBelowRoot(rest) + driveRootSlash(rest)
	} else if m := bashDrive.FindStringSubmatch(p); m != nil {
		return strings.ToUpper(m[1]) + ":" + cleanBelowRoot(p[2:])
	}
	return p
}

// driveRootSlash keeps the slash on a bare drive root, so C:/ still reads as a drive
// path; cleanBelowRoot returns nothing for it.
func driveRootSlash(rest string) string {
	if cleanBelowRoot(rest) == "" {
		return "/"
	}
	return ""
}

// cleanBelowRoot cleans what follows a drive or UNC root. The leading slash makes the
// root a ceiling that `..` cannot climb above, which is how Windows resolves it. The
// result is empty, or starts with a slash.
func cleanBelowRoot(rest string) string {
	parts := strings.Split(rest, "/")
	kept := parts[:0]
	for _, c := range parts {
		if c != "" && c != "." && c != ".." {
			if i := strings.IndexByte(c, ':'); i >= 0 {
				c = c[:i] // NTFS alternate data stream
			}
			if c = strings.TrimRight(c, ". "); c == "" {
				continue
			}
		}
		kept = append(kept, c)
	}
	if c := path.Clean("/" + strings.Join(kept, "/")); c != "/" {
		return c
	}
	return ""
}

// PathWithin reports whether p is inside dir, or is dir itself. Both are normalized
// first, so it holds across separator styles and, for Windows drive paths, across
// case. Comparison is by path segment: /src/myrepo-evil is not inside /src/myrepo,
// which a plain string-prefix test would say it is.
func PathWithin(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	return isUnder(normalize(p), normalize(dir))
}

// HighestZone returns the most severe zone among the given paths, which is the
// one that survives into the flattened event.
func HighestZone(zones []string) string {
	best := event.ZoneUnknown
	for _, z := range zones {
		if event.ZoneSeverity(z) > event.ZoneSeverity(best) {
			best = z
		}
	}
	return best
}
