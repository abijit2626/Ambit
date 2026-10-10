package redact

import (
	"regexp"
	"sort"
	"strings"
)

const Placeholder = "[REDACTED]"

type Hit struct {
	Kind  string
	Count int
}

type pattern struct {
	kind string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{"private_key_block", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"private_key_header", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,255}\b`)},
	{"github_pat", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{22,255}\b`)},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[0-9A-Za-z_\-]{20,}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprse]-[0-9A-Za-z\-]{10,}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},

	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{"openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`)},
	{"stripe_key", regexp.MustCompile(`\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b`)},
	{"npm_token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"basic_auth_url", regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@`)},

	{"generic_assignment", regexp.MustCompile(`(?i)[A-Za-z0-9_\-]{0,32}(?:api[_\-]?key|secret|passwd|password|token|auth|credential|private[_\-]?key)[A-Za-z0-9_\-]{0,32}["'\s]*[:=]["'\s]*([A-Za-z0-9/+_\-]{16,})`)},
}

type Redactor struct {
	patterns []pattern
}

func New() *Redactor { return &Redactor{patterns: patterns} }

func (r *Redactor) Scan(s string) []Hit {
	_, hits := r.Redact(s)
	return hits
}

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

func (r *Redactor) HasSecret(s string) bool {
	for _, p := range r.patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}
