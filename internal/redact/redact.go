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

	// need lists literals one of which every match contains, so text with none of them skips the
	// regexp. fold compares them against lowercased text, for a case-insensitive pattern.
	need []string
	fold bool
	also string
}

var patterns = []pattern{
	{"private_key_block", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), []string{"PRIVATE KEY-----"}, false, ""},
	{"private_key_header", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), []string{"PRIVATE KEY-----"}, false, ""},
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`), []string{"AKIA", "ASIA", "ABIA", "ACCA"}, false, ""},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,255}\b`), []string{"gh"}, false, ""},
	{"github_pat", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{22,255}\b`), []string{"github_pat_"}, false, ""},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[0-9A-Za-z_\-]{20,}\b`), []string{"glpat-"}, false, ""},
	{"slack_token", regexp.MustCompile(`\bxox[baprse]-[0-9A-Za-z\-]{10,}\b`), []string{"xox"}, false, ""},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), []string{"AIza"}, false, ""},

	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`), []string{"sk-ant-"}, false, ""},
	{"openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}\b`), []string{"sk-"}, false, ""},
	{"stripe_key", regexp.MustCompile(`\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b`), []string{"_live_", "_test_"}, false, ""},
	{"npm_token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`), []string{"npm_"}, false, ""},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), []string{"eyJ"}, false, ""},
	{"basic_auth_url", regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@`), []string{"://"}, false, "@"},

	{"generic_assignment", regexp.MustCompile(`(?i)[A-Za-z0-9_\-]{0,32}(?:api[_\-]?key|secret|passwd|password|token|auth|credential|private[_\-]?key)[A-Za-z0-9_\-]{0,32}["'\s]*[:=]["'\s]*([A-Za-z0-9/+_\-]{16,})`), []string{"key", "secret", "passwd", "password", "token", "auth", "credential"}, true, ""},
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
		if !p.mayMatch(out) {
			continue
		}
		out = p.re.ReplaceAllStringFunc(out, func(m string) string {
			counts[p.kind]++

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

func (p pattern) mayMatch(s string) bool {
	if p.also != "" && !strings.Contains(s, p.also) {
		return false
	}
	if len(p.need) == 0 {
		return true
	}
	if p.fold {
		if !strings.ContainsAny(s, ":=") {
			return false
		}
		s = strings.ReplaceAll(strings.ToLower(s), "ſ", "s")
	}
	for _, n := range p.need {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func (r *Redactor) HasSecret(s string) bool {
	for _, p := range r.patterns {
		if p.mayMatch(s) && p.re.MatchString(s) {
			return true
		}
	}
	return false
}
