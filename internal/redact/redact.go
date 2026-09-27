// Package redact detects and strips secret material at the endpoint, before
// anything is written to a sink.
//
// This runs on the way in, never on the way out. A redaction pass that runs at
// read time is a redaction pass that will eventually be skipped, and the
// consequence here is a secret reaching the SIEM — and, with a third-party
// monitoring the deployment, leaving our control entirely. See
// docs/04-data-model.md.
//
// Only the secret's KIND is ever recorded. The value is replaced in place and
// never travels in either representation.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Placeholder replaces detected secret material. Fixed-width and recognizable
// so a human reading a spooled event knows redaction happened rather than
// wondering whether the field was empty.
const Placeholder = "[REDACTED]"

// Hit records that a secret of a given kind was found, and how many times.
type Hit struct {
	Kind  string
	Count int
}

type pattern struct {
	kind string
	re   *regexp.Regexp
}

// patterns are ordered most-specific first. Provider-shaped tokens are matched
// before the generic assignment heuristic so a GitHub token is reported as
// github_token rather than generic_assignment.
var patterns = []pattern{
	{"private_key_block", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"private_key_header", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,255}\b`)},
	{"github_pat", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{22,255}\b`)},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[0-9A-Za-z_\-]{20,}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprse]-[0-9A-Za-z\-]{10,}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	// anthropic_key must precede openai_key: sk-ant- also matches the broader
	// sk- pattern, and whichever runs first wins the label.
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{"openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`)},
	{"stripe_key", regexp.MustCompile(`\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b`)},
	{"npm_token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"basic_auth_url", regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@`)},
	// Generic fallback: a secret-ish key assigned a long opaque value. Narrow
	// enough to avoid matching ordinary config, and it fires last.
	// The keyword is surrounded by optional identifier characters rather than
	// \b: a word boundary never fires inside DATABASE_PASSWORD, because _ is a
	// word character, so \bpassword\b misses the most common spelling of the
	// thing we are looking for.
	{"generic_assignment", regexp.MustCompile(`(?i)[A-Za-z0-9_\-]{0,32}(?:api[_\-]?key|secret|passwd|password|token|auth|credential|private[_\-]?key)[A-Za-z0-9_\-]{0,32}["'\s]*[:=]["'\s]*([A-Za-z0-9/+_\-]{16,})`)},
}

// Redactor strips secrets from text.
type Redactor struct {
	patterns []pattern
}

func New() *Redactor { return &Redactor{patterns: patterns} }

// Scan reports which secret kinds appear in s without modifying it. Use when
// only the kinds are needed, such as populating secret_hit_kinds.
func (r *Redactor) Scan(s string) []Hit {
	_, hits := r.Redact(s)
	return hits
}

// Redact replaces every detected secret with Placeholder and returns the
// cleaned text alongside the kinds found.
//
// Hits are returned sorted by kind so events are byte-stable across runs, which
// matters because event digests are compared.
func (r *Redactor) Redact(s string) (string, []Hit) {
	if s == "" {
		return "", nil
	}
	counts := map[string]int{}
	out := s
	for _, p := range r.patterns {
		matches := p.re.FindAllString(out, -1)
		if len(matches) == 0 {
			continue
		}
		counts[p.kind] += len(matches)
		out = p.re.ReplaceAllStringFunc(out, func(m string) string {
			// For the generic assignment pattern, keep the key name so the
			// event still says WHAT was set, and drop only the value.
			if p.kind == "generic_assignment" {
				if i := strings.IndexAny(m, ":="); i >= 0 {
					return m[:i+1] + Placeholder
				}
			}
			return Placeholder
		})
	}
	if len(counts) == 0 {
		return out, nil
	}
	hits := make([]Hit, 0, len(counts))
	for k, c := range counts {
		hits = append(hits, Hit{Kind: k, Count: c})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Kind < hits[j].Kind })
	return out, hits
}

// HasSecret reports whether any secret was detected. Used to set Rule-of-Two
// bit B when a read returns credential material from a path that was not itself
// in the credential zone.
func (r *Redactor) HasSecret(s string) bool {
	for _, p := range r.patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}
