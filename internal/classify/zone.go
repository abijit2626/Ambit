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
	return &Zoner{
		home:           normalize(home),
		workdir:        normalize(workdir),
		extraUntrusted: extraUntrusted,
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

// systemPrefixes are OS-owned trees.
var systemPrefixes = []string{
	"/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/proc/", "/sys/",
	"/System/", "/Library/", "/private/etc/",
}

// windowsSystem matches the OS-owned trees on a Windows drive, against a
// lower-cased, forward-slashed path. It is anchored to a drive letter on purpose:
// "windows" as a bare fragment would label a project directory that happens to be
// called windows as system. ProgramData is left out for the same reason /var is
// not in systemPrefixes: it is where programs keep data, not where the OS lives.
var windowsSystem = regexp.MustCompile(`^[a-z]:/(windows|program files|program files \(x86\))(/|$)`)

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
	if hasAnyFragment(lower, systemPrefixesAsFragments()) || hasAnyPrefix(p, systemPrefixes) || windowsSystem.MatchString(lower) {
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

// systemPrefixesAsFragments lets a system path be detected even when it appears
// under a container or chroot prefix.
func systemPrefixesAsFragments() []string { return systemPrefixes }

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

// normalize puts a path in one comparable form: forward slashes, cleaned, with
// Windows drive paths spelled X:/... whichever way they arrived.
//
// Separators are converted before cleaning rather than after. filepath.Clean only
// understands the host's separator, so on Linux `a\..\b` would survive uncleaned
// and a traversal written with backslashes could name a credential path that the
// zone check never saw. path.Clean works on forward slashes and behaves the same on
// every host, which is what lets the Windows cases be tested on Linux CI.
func normalize(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, "/")
	// Extended-length (\\?\C:\...) and device (\\.\C:\...) prefixes name the same
	// file as the plain path.
	if strings.HasPrefix(p, "//?/") || strings.HasPrefix(p, "//./") {
		p = p[4:]
	}
	unc := strings.HasPrefix(p, "//")
	p = path.Clean(p)
	if unc && !strings.HasPrefix(p, "//") {
		p = "/" + p // path.Clean collapses the leading pair that marks a UNC share
	}
	if m := wslMount.FindStringSubmatch(p); m != nil {
		p = strings.ToUpper(m[1]) + ":" + p[len(m[0])-len(m[2]):]
	} else if m := bashDrive.FindStringSubmatch(p); m != nil {
		p = strings.ToUpper(m[1]) + ":" + p[2:]
	}
	if len(p) == 2 && p[1] == ':' {
		p += "/" // path.Clean drops the slash from a drive root; keep it so it still reads as a drive path
	}
	return p
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
