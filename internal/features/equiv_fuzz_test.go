package features

import (
	"reflect"
	"strings"
	"testing"
)

// referenceSets is the extraction as it was before it ran per word: every pattern over the whole text.
func referenceSets(text string) (urls, domains, emails, ips, hi map[string]bool) {
	urls, domains, emails, ips, hi = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
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
	for _, m := range reHost.FindAllString(stripEmails(text), -1) {
		if !looksLikeFilename(m) {
			domains[Registrable(m)] = true
		}
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
	return
}

// Running the patterns per word is only an optimization: on any text the digests must be the ones the
// whole-text extraction produced.
func FuzzPerWordExtractionChangesNothing(f *testing.F) {
	for _, s := range []string{
		"See https://docs.example.com/x and mail ops@example.com from 10.0.0.1, key xK9fQ2mZp7LwR4vT8bNc3Yd5",
		"a@b.co\u00a0https://x.test/\u00a0y\vz",
		"user@mail.example.com.evil.test SERVICE_KEY=xK9fQ2mZp7LwR4vT8bNc3Yd5",
		"",
	} {
		f.Add(s)
	}
	e := New([]byte("fuzz-key-that-is-long-enough-abcdef"))
	f.Fuzz(func(t *testing.T, text string) {
		got := e.Extract(text)
		u, d, em, ip, hi := referenceSets(text)
		want := map[string][]string{"urls": e.digestSet(u), "domains": e.digestSet(d), "emails": e.digestSet(em), "ips": e.digestSet(ip), "hi": e.digestSet(hi)}
		have := map[string][]string{"urls": got.URLs, "domains": got.Domains, "emails": got.Emails, "ips": got.IPs, "hi": got.HiEntropy}
		for k := range want {
			if !reflect.DeepEqual(have[k], want[k]) && !(len(have[k]) == 0 && len(want[k]) == 0) {
				t.Fatalf("%s differ for %q:\ngot  %v\nwant %v", k, text, have[k], want[k])
			}
		}
	})
}
