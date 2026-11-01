package features

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net"
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

	// None of these patterns can match across the whitespace \s means, so each runs only on the words that
	// could hold a match. That gives the same matches as running it on the whole text, far more cheaply.
	words := strings.FieldsFunc(text, isRegexpSpace)
	for _, w := range words {
		if strings.Contains(w, "://") {
			for _, m := range reURL.FindAllString(w, -1) {
				urls[m] = true
				if h := hostFromURL(m); h != "" {
					domains[Registrable(h)] = true
				}
			}
		}
		hostWords := []string{w}
		if strings.Contains(w, "@") {
			for _, m := range reEmail.FindAllString(w, -1) {
				emails[strings.ToLower(m)] = true
				if i := strings.LastIndex(m, "@"); i >= 0 {
					domains[Registrable(m[i+1:])] = true
				}
			}
			hostWords = strings.FieldsFunc(stripEmails(w), isRegexpSpace)
		}
		if strings.Contains(w, ".") {
			for _, hw := range hostWords {
				for _, m := range reHost.FindAllString(hw, -1) {
					if looksLikeFilename(m) {
						continue
					}
					domains[Registrable(m)] = true
				}
			}
			for _, m := range reIPv4.FindAllString(w, -1) {
				ips[m] = true
			}
		}
		if len(w) >= MinEntropyTokenLen {
			for _, m := range reToken.FindAllString(w, -1) {
				for _, tok := range tokenVariants(m) {
					if shannonBits(tok) >= MinEntropyBits {
						hi[tok] = true
					}
				}
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

// Registrable is the part of host that one party registers: example.com for a.b.example.com, and
// example.co.uk or someone.github.io where the last two labels are a suffix anyone can register under.
// Treating those as the registrable part would make trusting one GitHub Pages site trust them all, and
// make every ngrok tunnel one destination.
//
// The suffixes are a short list of the common ones, not the whole public suffix list, to keep ambitd
// free of a dependency and a file to update. A suffix missing from it falls back to the last two
// labels, the old behaviour; one listed in error only narrows a match. Neither direction widens trust.
func Registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// An address has no registrable part: keeping the last two octets would make 10.0.3.4 and 1.2.3.4
	// one destination.
	if net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	keep := 2
	for n := maxSuffixLabels; n >= 2; n-- {
		if n < len(parts) && publicSuffixes[strings.Join(parts[len(parts)-n:], ".")] {
			keep = n + 1
			break
		}
	}
	return strings.Join(parts[len(parts)-keep:], ".")
}

const maxSuffixLabels = 4

// publicSuffixes holds multi-label suffixes from the public suffix list: country second levels, and
// hosting platforms where each customer gets a subdomain.
var publicSuffixes = func() map[string]bool {
	m := map[string]bool{}
	for _, group := range []string{
		// Country second levels.
		"co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk net.uk nhs.uk sch.uk police.uk",
		"com.au net.au org.au edu.au gov.au asn.au id.au",
		"co.nz org.nz net.nz govt.nz ac.nz school.nz",
		"co.jp ne.jp or.jp ac.jp go.jp ed.jp ad.jp gr.jp lg.jp",
		"co.kr or.kr ne.kr ac.kr go.kr re.kr",
		"co.in net.in org.in ac.in gov.in firm.in gen.in ind.in edu.in res.in",
		"co.za org.za gov.za ac.za net.za web.za",
		"com.br net.br org.br gov.br edu.br",
		"com.cn net.cn org.cn gov.cn edu.cn ac.cn",
		"com.hk org.hk net.hk edu.hk gov.hk",
		"com.sg net.sg org.sg edu.sg gov.sg",
		"com.tw org.tw net.tw edu.tw gov.tw",
		"com.mx org.mx gob.mx edu.mx net.mx",
		"com.ar org.ar gob.ar net.ar",
		"com.tr org.tr net.tr gov.tr edu.tr",
		"co.il org.il ac.il gov.il net.il",
		"com.my org.my net.my edu.my gov.my",
		"com.ph org.ph net.ph gov.ph edu.ph",
		"co.id or.id ac.id go.id web.id net.id",
		"co.th or.th ac.th go.th in.th net.th",
		"com.vn net.vn org.vn gov.vn edu.vn",
		"com.ua org.ua net.ua gov.ua",
		"com.pk org.pk net.pk gov.pk edu.pk",
		"com.eg org.eg gov.eg edu.eg",
		"com.ng org.ng gov.ng edu.ng",
		"com.sa org.sa gov.sa edu.sa",
		"com.co org.co net.co gov.co",
		"com.pl org.pl net.pl",
		// Hosting platforms: one subdomain per customer, so one per party.
		"github.io gitlab.io githubusercontent.com readthedocs.io",
		"herokuapp.com netlify.app vercel.app pages.dev workers.dev r2.dev",
		"appspot.com web.app firebaseapp.com cloudfront.net azurewebsites.net",
		"s3.amazonaws.com blob.core.windows.net",
		"ngrok.io ngrok.app ngrok-free.app trycloudflare.com",
		"blogspot.com glitch.me onrender.com fly.dev deno.dev pythonanywhere.com",
	} {
		for _, s := range strings.Fields(group) {
			m[s] = true
		}
	}
	return m
}()

func looksLikeFilename(s string) bool {
	parts := strings.Split(strings.ToLower(s), ".")
	return fileExtensions[parts[len(parts)-1]]
}

// isRegexpSpace is exactly the set \s matches in Go's regexp syntax.
func isRegexpSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\r'
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
