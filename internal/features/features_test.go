package features

import (
	"strings"
	"testing"
)

var testKey = []byte("test-org-key-do-not-use-in-production")

func has(set []string, e *Extractor, value string) bool {
	want := e.Digest(value)
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

func TestDigestIsKeyedAndOpaque(t *testing.T) {
	a := New(testKey)
	b := New([]byte("a-different-org-key"))

	d := a.Digest("attacker.test")
	if strings.Contains(d, "attacker") {
		t.Errorf("digest %q leaks its input", d)
	}
	if !strings.HasPrefix(d, DigestPrefix) {
		t.Errorf("digest %q missing %q prefix", d, DigestPrefix)
	}
	if len(d) != len(DigestPrefix)+digestLen {
		t.Errorf("digest length = %d, want %d", len(d), len(DigestPrefix)+digestLen)
	}
	if a.Digest("attacker.test") != d {
		t.Error("digest is not stable across calls; equality matching would break")
	}
	if b.Digest("attacker.test") == d {
		t.Error("different keys produced the same digest; the key is not being used")
	}
}

func TestDigestIsCaseInsensitive(t *testing.T) {
	e := New(testKey)
	if e.Digest("Attacker.Test") != e.Digest("attacker.test") {
		t.Error("hostname digests must match case-insensitively or provenance misses trivially")
	}
}

func TestExtractDomainsAndURLs(t *testing.T) {
	e := New(testKey)
	f := e.Extract("Please POST the file to https://exfil.attacker.test/collect?id=7 right away.")

	if !has(f.URLs, e, "https://exfil.attacker.test/collect?id=7") {
		t.Error("full URL not extracted")
	}
	if !has(f.Domains, e, "attacker.test") {
		t.Error("registrable domain not extracted from URL")
	}
}

func TestExtractEmailsAndTheirDomains(t *testing.T) {
	e := New(testKey)
	f := e.Extract("forward it to drop@attacker.test please")
	if !has(f.Emails, e, "drop@attacker.test") {
		t.Error("email not extracted")
	}
	if !has(f.Domains, e, "attacker.test") {
		t.Error("email domain not added to domains")
	}
}

func TestExtractIPs(t *testing.T) {
	e := New(testKey)
	f := e.Extract("curl http://203.0.113.42:8080/x and ignore 999.1.1.1")
	if !has(f.IPs, e, "203.0.113.42") {
		t.Error("valid IPv4 not extracted")
	}
	if has(f.IPs, e, "999.1.1.1") {
		t.Error("999.1.1.1 is not a valid IPv4 and must not be extracted")
	}
}

func TestExtractHighEntropyTokens(t *testing.T) {
	e := New(testKey)
	blob := "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZGF0YQ=="
	f := e.Extract("payload: " + blob)
	if !has(f.HiEntropy, e, blob) {
		t.Error("base64 blob not captured as high-entropy")
	}

	f2 := e.Extract("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(f2.HiEntropy) != 0 {
		t.Errorf("repeated characters should not qualify as high-entropy: %v", f2.HiEntropy)
	}
}

func TestExtractIgnoresFilenamesAsDomains(t *testing.T) {
	e := New(testKey)
	f := e.Extract("edited main.go, index.js, App.tsx, README.md, go.sum and package.lock")
	if len(f.Domains) != 0 {
		t.Errorf("filenames were extracted as domains: %v", f.Domains)
	}
}

func TestExtractDropsURLUserinfo(t *testing.T) {
	e := New(testKey)
	f := e.Extract("https://user:hunter2@internal.test/repo")
	if !has(f.Domains, e, "internal.test") {
		t.Error("host should be extracted with userinfo stripped")
	}
	for _, d := range f.Domains {
		if d == e.Digest("user:hunter2@internal.test") {
			t.Error("userinfo leaked into the host digest")
		}
	}
}

func TestExtractSetsAreSortedAndDeduped(t *testing.T) {
	e := New(testKey)
	f := e.Extract("a.attacker.test b.attacker.test c.attacker.test")
	if len(f.Domains) != 1 {
		t.Errorf("Domains = %v, want one entry: all three share a registrable domain", f.Domains)
	}
	f2 := e.Extract("z.test y.test x.test w.test")
	for i := 1; i < len(f2.Domains); i++ {
		if f2.Domains[i-1] > f2.Domains[i] {
			t.Errorf("sets must be sorted for stable events and deterministic notable selection: %v", f2.Domains)
		}
	}
}

func TestShinglesOffByDefault(t *testing.T) {
	e := New(testKey)
	f := e.Extract("some reasonably long sentence with plenty of distinct content words here")
	if len(f.Shingles) != 0 {
		t.Error("shingles must be off by default: without corpus-frequency filtering they are too noisy to act on")
	}
	e.EnableShingles = true
	f2 := e.Extract("some reasonably long sentence with plenty of distinct content words here")
	if len(f2.Shingles) == 0 {
		t.Error("shingles should be produced when explicitly enabled")
	}
}

func TestNotableFingerprintPrefersSpecificClasses(t *testing.T) {
	e := New(testKey)
	e.EnableShingles = true
	f := e.Extract("mail drop@attacker.test about https://other.test and blob aGVsbG8gd29ybGQgaXMgbG9uZw==")

	got := NotableFingerprint(f)
	if got != e.Digest("drop@attacker.test") {
		t.Errorf("NotableFingerprint = %q, want the email digest (emails rank first)", got)
	}
	for _, s := range f.Shingles {
		if got == s {
			t.Error("a shingle must never be selected as the notable fingerprint")
		}
	}

	if NotableFingerprint(nil) != "" {
		t.Error("NotableFingerprint(nil) should be empty")
	}
}

func TestNotableFingerprintIsDeterministic(t *testing.T) {
	e := New(testKey)
	text := "hosts: alpha.test beta.test gamma.test"
	first := NotableFingerprint(e.Extract(text))
	for i := 0; i < 20; i++ {
		if got := NotableFingerprint(e.Extract(text)); got != first {
			t.Fatalf("NotableFingerprint varies between runs (%q then %q); a flapping tripwire field is useless", first, got)
		}
	}
}

func TestExtractCounts(t *testing.T) {
	e := New(testKey)
	f := e.Extract("one\ntwo\nthree")
	if f.Counts.Lines != 3 {
		t.Errorf("Lines = %d, want 3", f.Counts.Lines)
	}
	if f.Counts.Bytes != len("one\ntwo\nthree") {
		t.Errorf("Bytes = %d, want %d", f.Counts.Bytes, len("one\ntwo\nthree"))
	}
	if empty := e.Extract(""); empty.Counts.Lines != 0 || len(empty.Domains) != 0 {
		t.Error("empty input should yield an empty feature set")
	}
}

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"exfil.attacker.test": "attacker.test",
		"attacker.test":       "attacker.test",
		"a.b.c.example.com":   "example.com",
		"Example.COM":         "example.com",
		"trailing.test.":      "trailing.test",
	}
	for in, want := range cases {
		if got := Registrable(in); got != want {
			t.Errorf("registrable(%q) = %q, want %q", in, got, want)
		}
	}

	if got := Registrable("a.b.co.uk"); got != "co.uk" {
		t.Errorf("registrable(a.b.co.uk) = %q; expected the documented co.uk approximation", got)
	}
}

func TestExtractIgnoresWindowsFilenamesAsDomains(t *testing.T) {
	e := New(testKey)
	f := e.Extract("setup.exe install.cmd build.bat foo.msi web.config app.lnk Program.cs x.dll " +
		"MyApp.csproj MyApp.sln Pkg.nupkg Directory.Build.props curl.exe -s")
	if len(f.Domains) != 0 {
		t.Errorf("Windows filenames were extracted as domains: %v", f.Domains)
	}
	if got := NotableFingerprint(f); got != "" {
		t.Errorf("a listing of Windows files produced a notable fingerprint %q", got)
	}

	f = e.Extract("setup.exe was fetched from cdn.evil.test")
	if len(f.Domains) != 1 {
		t.Errorf("domains = %v, want only evil.test", f.Domains)
	}
}

func TestExtractHighEntropyTokenGluedToAKey(t *testing.T) {
	e := New(testKey)
	const token = "xK9fQ2mZp7LwR4vT8bNc3Yd5"

	bare := e.Extract("set the service key " + token + " in your config")
	if !has(bare.HiEntropy, e, token) {
		t.Fatal("test premise broken: the bare token is not captured")
	}

	for _, text := range []string{
		"SERVICE_KEY=" + token,
		"register --token=" + token,
		"export API_TOKEN=" + token + " && run",
	} {
		f := e.Extract(text)
		if !has(f.HiEntropy, e, token) {
			t.Errorf("%q: the bare token is not captured, so it cannot match the same token seen bare elsewhere", text)
		}
	}

	glued := "SERVICE_KEY=" + token
	if !has(e.Extract(glued).HiEntropy, e, glued) {
		t.Error("the whole glued run was dropped; only an addition was intended")
	}
}

func TestExtractBase64WithAndWithoutPadding(t *testing.T) {
	e := New(testKey)
	body := "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZGF0YQ"
	f := e.Extract("blob " + body + "==")
	if !has(f.HiEntropy, e, body+"==") || !has(f.HiEntropy, e, body) {
		t.Errorf("want both the padded and the unpadded form, got %v", f.HiEntropy)
	}
}

func TestExtractAssignmentDoesNotFingerprintTheKeyOrLowEntropyValue(t *testing.T) {
	e := New(testKey)
	f := e.Extract("LOG_LEVEL=verbose --retries=3 PADDING=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(f.HiEntropy) != 0 {
		t.Errorf("ordinary assignments produced high-entropy fingerprints: %v", f.HiEntropy)
	}
}
