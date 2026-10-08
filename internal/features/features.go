// Package features extracts the fingerprints the provenance layer intersects.
//
// Every fingerprint is HMAC'd with a per-org key rather than plain-hashed.
// Plain SHA-256 of a short low-entropy value — a domain, an email — is trivially
// brute-forced, which would turn the event store into a confirmable list of
// every domain and address the fleet ever touched. With a third party holding a
// copy of that store, keying is what keeps equality-matching possible without
// handing over the values. The key is ours and is not shared. See
// docs/04-data-model.md.
//
// Raw fingerprints never cross to the SIEM. ambitd intersects locally and emits
// only derived edges plus one notable fingerprint.
package features

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/abijit2626/ambit/internal/event"
)

// DigestPrefix marks a keyed digest so a reader never mistakes one for a value.
const DigestPrefix = "hmac:"

// digestLen is the hex length kept from each HMAC. 32 hex chars is 128 bits:
// collision-safe for equality matching at fleet scale while keeping events
// narrow, which matters because event width is a decoder constraint.
const digestLen = 32

// MinEntropyTokenLen and MinEntropyBits gate the high-entropy fingerprint
// class. Tuned to catch keys, blobs and opaque IDs without collecting every
// long identifier in a source tree.
const (
	MinEntropyTokenLen = 20
	MinEntropyBits     = 3.2
)

var (
	// reURL is deliberately permissive on the path: the registrable domain is
	// the high-specificity part, and the full URL is a separate class.
	reURL   = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]{1,31}://[^\s"'<>\)\]}]+`)
	reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	reHost  = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b`)
	reIPv4  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	reToken = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{` + itoa(MinEntropyTokenLen) + `,}`)
	reWord  = regexp.MustCompile(`[A-Za-z0-9_\-]+`)
)

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// commonTLDish filters hostname matches that are really filenames. Without this,
// every `main.go` and `index.js` becomes a "domain" fingerprint and the
// provenance intersection fills with noise.
var fileExtensions = map[string]bool{
	"go": true, "js": true, "ts": true, "tsx": true, "jsx": true, "py": true,
	"rs": true, "java": true, "rb": true, "php": true, "c": true, "h": true,
	"cpp": true, "hpp": true, "cs": true, "sh": true, "md": true, "txt": true,
	"json": true, "yaml": true, "yml": true, "toml": true, "xml": true,
	"html": true, "css": true, "scss": true, "lock": true, "sum": true,
	"mod": true, "cfg": true, "ini": true, "env": true, "log": true,
	"png": true, "jpg": true, "svg": true, "gif": true, "pdf": true,
	"zip": true, "tar": true, "gz": true, "so": true, "dylib": true, "dll": true,
	"map": true, "bak": true, "tmp": true,
	// Windows. A directory listing or a build log is full of these, and each would
	// otherwise be fingerprinted as a domain: setup.exe, web.config, install.cmd.
	// None is a delegated top-level domain.
	"exe": true, "cmd": true, "bat": true, "msi": true, "msix": true, "appx": true,
	"lnk": true, "config": true, "vbs": true, "sys": true, "ocx": true, "cab": true,
	"pdb": true, "resx": true, "csproj": true, "vbproj": true, "fsproj": true,
	"sln": true, "nupkg": true, "props": true, "targets": true, "manifest": true,
	"reg": true, "inf": true, "ico": true,
}

// Deliberately absent from fileExtensions: "test", "spec" and "min". Those
// appear as MIDDLE labels in real filenames (App.test.tsx, app.min.js), where
// the final extension already excludes them, and treating them as final
// extensions would swallow the .test TLD that RFC 6761 reserves for examples.
// A file literally named foo.test would be fingerprinted as a domain; that is
// rare, and cheaper than losing a whole TLD.

// stopWords are excluded from shingles so common prose does not dominate.
var stopWords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
	"if": true, "then": true, "else": true, "for": true, "to": true, "of": true,
	"in": true, "on": true, "at": true, "by": true, "with": true, "from": true,
	"is": true, "are": true, "was": true, "were": true, "be": true, "been": true,
	"this": true, "that": true, "it": true, "as": true, "not": true, "you": true,
	"we": true, "i": true, "he": true, "she": true, "they": true, "will": true,
	"can": true, "do": true, "does": true, "have": true, "has": true, "all": true,
}

// Extractor computes keyed fingerprints.
type Extractor struct {
	key []byte
	// ShingleN is the n-gram width. Shingles are advisory-only per
	// docs/03-detection.md and are off by default: without corpus-frequency
	// filtering they are too noisy to act on, and that corpus does not exist
	// yet.
	ShingleN       int
	EnableShingles bool
}

func New(key []byte) *Extractor {
	return &Extractor{key: key, ShingleN: 5, EnableShingles: false}
}

// Digest returns the keyed digest of a value, normalized to lower case so
// equality matching is case-insensitive for hostnames and emails.
func (e *Extractor) Digest(value string) string {
	m := hmac.New(sha256.New, e.key)
	m.Write([]byte(strings.ToLower(value)))
	return DigestPrefix + hex.EncodeToString(m.Sum(nil))[:digestLen]
}

// Extract computes the fingerprint set for a piece of text.
func (e *Extractor) Extract(text string) *event.Features {
	f := &event.Features{
		Counts: event.Counts{Bytes: len(text), Lines: countLines(text)},
	}
	if text == "" {
		return f
	}

	urls := map[string]bool{}
	domains := map[string]bool{}
	emails := map[string]bool{}
	ips := map[string]bool{}
	hi := map[string]bool{}

	for _, m := range reURL.FindAllString(text, -1) {
		urls[m] = true
		if h := hostFromURL(m); h != "" {
			domains[Registrable(h)] = true
		}
	}
	for _, m := range reEmail.FindAllString(text, -1) {
		emails[strings.ToLower(m)] = true
		if i := strings.LastIndex(m, "@"); i >= 0 {
			domains[Registrable(m[i+1:])] = true
		}
	}
	// Bare hostnames, excluding anything that is really a filename.
	emailDomainsOnly := stripEmails(text)
	for _, m := range reHost.FindAllString(emailDomainsOnly, -1) {
		if looksLikeFilename(m) {
			continue
		}
		domains[Registrable(m)] = true
	}
	for _, m := range reIPv4.FindAllString(text, -1) {
		ips[m] = true
	}
	for _, m := range reToken.FindAllString(text, -1) {
		for _, tok := range tokenVariants(m) {
			if shannonBits(tok) >= MinEntropyBits {
				hi[tok] = true
			}
		}
	}

	f.URLs = e.digestSet(urls)
	f.Domains = e.digestSet(domains)
	f.Emails = e.digestSet(emails)
	f.IPs = e.digestSet(ips)
	f.HiEntropy = e.digestSet(hi)
	f.IBANs = e.digestSet(ibans(text))
	if e.EnableShingles {
		f.Shingles = e.digestSet(shingleSet(text, e.ShingleN))
	}
	return f
}

// NotableFingerprint picks at most one high-specificity fingerprint to carry as
// the scalar prov_fp_notable field.
//
// This exists because Wazuh's same_field is scalar equality and cannot express
// the set intersection D10 actually needs; the scalar is a cheap first-pass
// tripwire and the real intersection stays out of the SIEM. See
// docs/03-detection.md on the D10 investigation.
//
// Only the specific classes qualify. Shingles and bare hostnames are too noisy
// to page on, so an IBAN, email, domain or high-entropy token is chosen, in that
// order. An IBAN comes first: it is checksum-validated, so it is the most specific
// value the extractor produces, and one account number turning up across agents is
// exactly the propagation D10 exists to notice.
func NotableFingerprint(f *event.Features) string {
	if f == nil {
		return ""
	}
	for _, set := range [][]string{f.IBANs, f.Emails, f.Domains, f.HiEntropy} {
		if len(set) > 0 {
			return set[0] // sets are sorted, so the choice is deterministic
		}
	}
	return ""
}

func (e *Extractor) digestSet(in map[string]bool) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for v := range in {
		out = append(out, e.Digest(v))
	}
	// Sorted so events are byte-stable and NotableFingerprint is deterministic.
	sort.Strings(out)
	return out
}

// tokenVariants returns the candidates a matched run yields: the run itself, and each
// '='-separated segment long enough to qualify on its own.
//
// reToken's class includes '=' so that base64 padding stays attached, but '=' is also
// how a value is glued to its key: SERVICE_KEY=<token> in a config file, --token=<token>
// on a command line. Left whole, that run digests differently from the bare token the
// ingested page carried, and the provenance intersection misses the most common way a
// credential actually travels. The whole run is kept as well, so a token that really does
// contain '=' still matches itself.
func tokenVariants(run string) []string {
	if !strings.Contains(run, "=") {
		return []string{run}
	}
	out := []string{run}
	for _, part := range strings.Split(run, "=") {
		if part != run && len(part) >= MinEntropyTokenLen {
			out = append(out, part)
		}
	}
	return out
}

func hostFromURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[at+1:] // drop userinfo
	}
	for _, sep := range []string{"/", "?", "#", ":"} {
		if j := strings.Index(rest, sep); j >= 0 {
			rest = rest[:j]
		}
	}
	return strings.ToLower(rest)
}

// registrable reduces a hostname to its last two labels. This is an
// approximation, not a public-suffix-list lookup: it collapses
// "a.b.co.uk" to "co.uk", which over-merges under multi-label suffixes. The
// consequence is a coarser match, not a missed one, and adopting a PSL is a
// later refinement.
// Registrable reduces a hostname to its registrable domain (the last two
// labels; "api.example.com" and "example.com" both become "example.com").
// Exported so a caller normalizing an operator-configured domain — before
// digesting it for comparison against an extracted one — applies exactly the
// reduction Extract applies internally, rather than a second implementation
// that could drift from this one. See internal/config's
// TrustedContentDomains and internal/collector's use of it.
func Registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func looksLikeFilename(s string) bool {
	parts := strings.Split(strings.ToLower(s), ".")
	return fileExtensions[parts[len(parts)-1]]
}

func stripEmails(text string) string {
	return reEmail.ReplaceAllString(text, " ")
}

func shingleSet(text string, n int) map[string]bool {
	words := reWord.FindAllString(strings.ToLower(text), -1)
	kept := make([]string, 0, len(words))
	for _, w := range words {
		if !stopWords[w] {
			kept = append(kept, w)
		}
	}
	out := map[string]bool{}
	for i := 0; i+n <= len(kept); i++ {
		out[strings.Join(kept[i:i+n], " ")] = true
	}
	return out
}

// shannonBits returns Shannon entropy per character in bits.
func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}
