package classify

import (
	"path"
	"regexp"
	"runtime"
	"strings"

	"github.com/abijit2626/ambit/internal/event"
)

type Zoner struct {
	home    string
	workdir string

	extraUntrusted []string
}

func NewZoner(home, workdir string, extraUntrusted []string) *Zoner {

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

var credentialBasenames = map[string]bool{
	".npmrc":           true,
	".netrc":           true,
	".pgpass":          true,
	".git-credentials": true,
	"credentials":      true,
	".htpasswd":        true,
	"id_rsa":           true,
	"id_dsa":           true,
	"id_ecdsa":         true,
	"id_ed25519":       true,
}

var credentialExts = map[string]bool{
	".pem":      true,
	".key":      true,
	".p12":      true,
	".pfx":      true,
	".jks":      true,
	".keystore": true,
	".kdbx":     true,
}

var credentialDirs = map[string][]string{
	"/.ssh/":           {"config", "known_hosts", "known_hosts.old", "authorized_keys"},
	"/.aws/":           nil,
	"/.gnupg/":         nil,
	"/.config/gcloud/": nil,
	"/.azure/":         nil,
	"/.kube/":          nil,
	"/.docker/":        nil,
	"/.config/gh/":     nil,

	"/appdata/roaming/gcloud/":                nil,
	"/appdata/roaming/github cli/":            nil,
	"/appdata/roaming/microsoft/credentials/": nil,
	"/appdata/local/microsoft/credentials/":   nil,
	"/appdata/roaming/microsoft/protect/":     nil,
	"/appdata/roaming/microsoft/crypto/":      nil,
	"/windows/system32/config/":               nil,
}

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

var systemPrefixes = []string{
	"/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/proc/", "/sys/",
	"/System/", "/Library/", "/private/etc/",
}

var windowsSystem = regexp.MustCompile(`^[a-z]:/(windows|program files|program files \(x86\)|progra~[12])(/|$)`)

var windowsDrive = regexp.MustCompile(`^[A-Za-z]:/`)

var wslMount = regexp.MustCompile(`^/mnt/([A-Za-z])(/|$)`)

var bashDrive = regexp.MustCompile(`(?i)^/([a-z])/(users|windows|program files|program files \(x86\)|programdata)(/|$)`)

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

	if hasAnyFragment(lower, systemPrefixes) {
		return event.ZoneSystem
	}
	return event.ZoneUnknown
}

func isCredential(lowerPath, base string) bool {

	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return true
	}
	if credentialBasenames[base] {
		return true
	}
	if credentialExts[strings.ToLower(path.Ext(base))] {
		return true
	}

	if strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") {
		return true
	}
	for dir, nonSecret := range credentialDirs {
		if !strings.Contains(lowerPath, dir) {
			continue
		}

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

func isUnder(p, dir string) bool {

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

var hostIsWindows = runtime.GOOS == "windows"

var nativeDrive = regexp.MustCompile(`^[A-Za-z]:(/|$)`)

func normalize(p string) string {
	if p == "" {
		return ""
	}
	backslashRoot := p[0] == '\\'
	p = strings.ReplaceAll(p, `\`, "/")

	unc := false

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

func driveRootSlash(rest string) string {
	if cleanBelowRoot(rest) == "" {
		return "/"
	}
	return ""
}

func cleanBelowRoot(rest string) string {
	parts := strings.Split(rest, "/")
	kept := parts[:0]
	for _, c := range parts {
		if c != "" && c != "." && c != ".." {
			if i := strings.IndexByte(c, ':'); i >= 0 {
				c = c[:i]
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

func PathWithin(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	return isUnder(normalize(p), normalize(dir))
}

func HighestZone(zones []string) string {
	best := event.ZoneUnknown
	for _, z := range zones {
		if event.ZoneSeverity(z) > event.ZoneSeverity(best) {
			best = z
		}
	}
	return best
}
