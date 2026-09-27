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
	"path/filepath"
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

// Zone returns the zone label for a path.
//
// Precedence is deliberate and not merely a match order: credential outranks
// everything, so a .env inside node_modules is a credential read rather than a
// dependency read, and a .env in the working directory does not get downgraded
// to workdir. Getting this backwards would let the highest-severity signal in
// the system hide behind a lower-severity label.
func (z *Zoner) Zone(path string) string {
	if path == "" {
		return event.ZoneUnknown
	}
	p := normalize(path)
	lower := strings.ToLower(p)
	base := strings.ToLower(filepath.Base(p))

	if isCredential(lower, base) {
		return event.ZoneCredential
	}
	if hasAnyFragment(lower, systemPrefixesAsFragments()) || hasAnyPrefix(p, systemPrefixes) {
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
	if credentialExts[strings.ToLower(filepath.Ext(base))] {
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
	if p == dir {
		return true
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return strings.HasPrefix(p, dir)
}

func normalize(p string) string {
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	// Normalize Windows separators so WSL2 paths compare predictably.
	return strings.ReplaceAll(p, `\`, "/")
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
