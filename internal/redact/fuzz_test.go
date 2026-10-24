package redact

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzRedactIsAFixedPoint(f *testing.F) {
	for _, s := range []string{
		"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
		"token: ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		"https://user:hunter2@example.com/x",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
		"password = [REDACTED]",
		"",
	} {
		f.Add(s)
	}
	r := New()
	f.Fuzz(func(t *testing.T, s string) {
		once, _ := r.Redact(s)
		twice, hits := r.Redact(once)
		if twice != once {
			t.Fatalf("a second pass changed the output, so the first left secret material:\nin    %q\nonce  %q\ntwice %q (%v)", s, once, twice, hits)
		}
	})
}

func isWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

func delimited(prefix, suffix string) bool {
	if p := []rune(prefix); len(p) > 0 && isWord(p[len(p)-1]) {
		return false
	}
	if s := []rune(suffix); len(s) > 0 && (isWord(s[0]) || s[0] == '-') {
		return false
	}
	return true
}

func FuzzRedactStripsADelimitedSecret(f *testing.F) {
	secrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		"xoxb-1234567890-abcdefghij",
		"sk-ant-api03-abcdefghijklmnopqrstuvwx",
		"glpat-abcdefghij1234567890",
	}
	for i := range secrets {
		f.Add(uint8(i), "export X=", "\n")
		f.Add(uint8(i), "", "")
		f.Add(uint8(i), "\"", "\"")
	}
	r := New()
	f.Fuzz(func(t *testing.T, which uint8, prefix, suffix string) {
		secret := secrets[int(which)%len(secrets)]
		if !delimited(prefix, suffix) {
			t.Skip()
		}
		in := prefix + secret + suffix
		out, _ := r.Redact(in)
		if strings.Contains(out, secret) {
			t.Fatalf("secret survived redaction:\nin  %q\nout %q", in, out)
		}
	})
}

// referenceRedact is Redact without the literal prefilters: every pattern's regexp runs on every input.
func referenceRedact(s string) string {
	out := s
	for _, p := range patterns {
		out = p.re.ReplaceAllStringFunc(out, func(m string) string {
			if p.kind == "generic_assignment" {
				if i := strings.IndexAny(m, ":="); i >= 0 {
					return m[:i+1] + Placeholder
				}
			}
			return Placeholder
		})
	}
	return out
}

// The prefilters only skip work: on any input, Redact must produce exactly what running every regexp does.
func FuzzPrefilterChangesNothing(f *testing.F) {
	for _, s := range []string{
		"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
		"ſecret: abcdefghijklmnopqrstuvwxyz012345",
		"Key=abcdefghijklmnopqrstuvwxyz012345",
		"Password = hunter2hunter2hunter2",
		"https://user:pw@example.com",
		"-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----",
		"plain text with no secret at all",
	} {
		f.Add(s)
	}
	r := New()
	f.Fuzz(func(t *testing.T, s string) {
		got, _ := r.Redact(s)
		if want := referenceRedact(s); got != want {
			t.Fatalf("prefilter changed the output:\nin   %q\ngot  %q\nwant %q", s, got, want)
		}
	})
}
