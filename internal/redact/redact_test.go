package redact

import (
	"strings"
	"testing"
)

func kinds(hits []Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Kind)
	}
	return out
}

func TestRedactDetectsAndStrips(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		kind   string
		secret string
	}{
		{"aws key id", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "aws_access_key_id", "AKIAIOSFODNN7EXAMPLE"},
		{"github token", "token: ghp_" + strings.Repeat("a", 36), "github_token", "ghp_" + strings.Repeat("a", 36)},
		{"github pat", "GITHUB_PAT=github_pat_" + strings.Repeat("b", 30), "github_pat", "github_pat_" + strings.Repeat("b", 30)},
		{"slack", "xoxb-123456789012-abcdefghijkl", "slack_token", "xoxb-123456789012-abcdefghijkl"},
		{"google", "key=AIza" + strings.Repeat("c", 35), "google_api_key", "AIza" + strings.Repeat("c", 35)},
		{"anthropic", "sk-ant-" + strings.Repeat("d", 40), "anthropic_key", "sk-ant-" + strings.Repeat("d", 40)},
		{"stripe", "sk_live_" + strings.Repeat("e", 24), "stripe_key", "sk_live_" + strings.Repeat("e", 24)},
		{"npm", "npm_" + strings.Repeat("f", 36), "npm_token", "npm_" + strings.Repeat("f", 36)},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", "jwt", "eyJhbGciOiJIUzI1NiIs"},
		{"basic auth url", "git clone https://user:hunter2@github.com/x/y", "basic_auth_url", "hunter2"},
	}

	r := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, hits := r.Redact(c.in)
			if len(hits) == 0 {
				t.Fatalf("no secret detected in %q", c.in)
			}
			found := false
			for _, k := range kinds(hits) {
				if k == c.kind {
					found = true
				}
			}
			if !found {
				t.Errorf("kinds = %v, want to include %q", kinds(hits), c.kind)
			}
			if strings.Contains(out, c.secret) {
				t.Errorf("secret value survived redaction: %q still contains %q", out, c.secret)
			}
			if !strings.Contains(out, Placeholder) {
				t.Errorf("output %q has no placeholder", out)
			}
		})
	}
}

func TestRedactPrivateKeyBlock(t *testing.T) {
	in := "prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nsuffix"
	out, hits := New().Redact(in)
	if len(hits) == 0 || hits[0].Kind != "private_key_block" {
		t.Fatalf("kinds = %v, want private_key_block", kinds(hits))
	}
	if strings.Contains(out, "b3BlbnNzaC1rZXktdjEAAAAA") {
		t.Errorf("key body survived: %q", out)
	}
	if !strings.Contains(out, "prefix") || !strings.Contains(out, "suffix") {
		t.Errorf("redaction ate surrounding context: %q", out)
	}
}

// TestRedactKeepsKeyNameDropsValue: an event should still say WHAT was set, so
// a reviewer can tell an AWS secret from a database password, while the value
// itself is gone.
func TestRedactKeepsKeyNameDropsValue(t *testing.T) {
	out, hits := New().Redact(`DATABASE_PASSWORD="s3cr3tvalue_longenough_here"`)
	if len(hits) == 0 {
		t.Fatal("generic assignment not detected")
	}
	if strings.Contains(out, "s3cr3tvalue_longenough_here") {
		t.Errorf("value survived: %q", out)
	}
	if !strings.Contains(out, "DATABASE_PASSWORD") {
		t.Errorf("key name should survive for triage: %q", out)
	}
}

// TestRedactNoFalsePositivesOnOrdinaryCode is the noise check. Over-matching
// here means secret_hit_kinds fires on ordinary source, which crosses events to
// the SIEM that should have stayed local and trains reviewers to ignore the
// field.
func TestRedactNoFalsePositivesOnOrdinaryCode(t *testing.T) {
	benign := []string{
		`func main() { fmt.Println("hello world") }`,
		`import { useState } from "react";`,
		`const timeout = 30 // seconds`,
		`git commit -m "fix: handle nil pointer in parser"`,
		`SELECT id, name FROM users WHERE active = true`,
		`// TODO: refactor this into a separate module`,
		`password: ${DB_PASSWORD}`,
		`token = os.Getenv("API_TOKEN")`,
		`https://github.com/abijit2626/indirect-prompt`,
		`sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
	}
	r := New()
	for _, s := range benign {
		if hits := r.Scan(s); len(hits) > 0 {
			t.Errorf("false positive on %q: %v", s, kinds(hits))
		}
	}
}

func TestRedactHitsAreSortedForStableDigests(t *testing.T) {
	in := "npm_" + strings.Repeat("f", 36) + " AKIAIOSFODNN7EXAMPLE ghp_" + strings.Repeat("a", 36)
	_, hits := New().Redact(in)
	got := kinds(hits)
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("hits not sorted: %v — event digests would not be reproducible", got)
		}
	}
}

func TestRedactEmpty(t *testing.T) {
	out, hits := New().Redact("")
	if out != "" || hits != nil {
		t.Errorf("Redact(\"\") = (%q, %v), want (\"\", nil)", out, hits)
	}
}

func TestHasSecret(t *testing.T) {
	r := New()
	if !r.HasSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Error("HasSecret should detect an AWS key id")
	}
	if r.HasSecret("just some ordinary prose about nothing") {
		t.Error("HasSecret false positive on prose")
	}
}
