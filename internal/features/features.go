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

const DigestPrefix = "hmac:"

const digestLen = 32

const (
	MinEntropyTokenLen = 20
	MinEntropyBits     = 3.2
)

var (
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

	"exe": true, "cmd": true, "bat": true, "msi": true, "msix": true, "appx": true,
	"lnk": true, "config": true, "vbs": true, "sys": true, "ocx": true, "cab": true,
	"pdb": true, "resx": true, "csproj": true, "vbproj": true, "fsproj": true,
	"sln": true, "nupkg": true, "props": true, "targets": true, "manifest": true,
	"reg": true, "inf": true, "ico": true,
}

var stopWords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
	"if": true, "then": true, "else": true, "for": true, "to": true, "of": true,
	"in": true, "on": true, "at": true, "by": true, "with": true, "from": true,
	"is": true, "are": true, "was": true, "were": true, "be": true, "been": true,
	"this": true, "that": true, "it": true, "as": true, "not": true, "you": true,
	"we": true, "i": true, "he": true, "she": true, "they": true, "will": true,
	"can": true, "do": true, "does": true, "have": true, "has": true, "all": true,
}

type Extractor struct {
	key []byte

	ShingleN       int
	EnableShingles bool
}

func New(key []byte) *Extractor {
	return &Extractor{key: key, ShingleN: 5, EnableShingles: false}
}

func (e *Extractor) Digest(value string) string {
	m := hmac.New(sha256.New, e.key)
	m.Write([]byte(strings.ToLower(value)))
	return DigestPrefix + hex.EncodeToString(m.Sum(nil))[:digestLen]
}

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

func NotableFingerprint(f *event.Features) string {
	if f == nil {
		return ""
	}
	for _, set := range [][]string{f.IBANs, f.Emails, f.Domains, f.HiEntropy} {
		if len(set) > 0 {
			return set[0]
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

	sort.Strings(out)
	return out
}

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
		rest = rest[at+1:]
	}
	for _, sep := range []string{"/", "?", "#", ":"} {
		if j := strings.Index(rest, sep); j >= 0 {
			rest = rest[:j]
		}
	}
	return strings.ToLower(rest)
}

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
