// Package labelsuggest drafts mcp_tool_labels entries from a server's recorded tool surface.
//
// A draft is never more permissive than the default for an unclassified tool except in one
// way, and that way needs two independent signals. Every suggestion carries "untrusted": a
// labelled tool's bits come from its labels alone, so leaving that label off declares that the
// tool's results never hold text someone else wrote, and only a person who knows the tool can say
// that. "read_only" removes the "acts" bit, and is suggested only when the server's readOnlyHint
// and the tool's name agree and nothing marks the tool as destructive. "sensitive" adds a bit, so
// it is suggested on a single piece of evidence. A tool with no suggestion of its own is left out
// of the draft and so keeps the server default, which is the worst case.
//
// The inputs are all written by the server. Tool descriptions in particular are what a poisoned
// server controls, so a description can add "sensitive" but can never relax anything.
package labelsuggest

import (
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/config"
)

type Suggestion struct {
	Tool string `json:"tool"`

	// Labels is what the draft would set; empty means the tool is left at the server default.
	Labels []string `json:"labels,omitempty"`

	// Reasons say what each label rests on, and what stopped a label from being suggested.
	Reasons []string `json:"reasons"`
}

// Relaxes reports whether the draft makes the tool less restricted than an unclassified one.
func (s Suggestion) Relaxes() bool {
	for _, l := range s.Labels {
		if l == config.LabelReadOnly {
			return true
		}
	}
	return false
}

var readVerbs = set("get", "list", "read", "search", "find", "fetch", "describe", "show", "view", "query", "lookup", "count", "check")

// A name containing any of these is not read-only whatever its prefix says: "get_and_delete".
var actVerbs = set("set", "put", "post", "send", "write", "create", "update", "delete", "remove",
	"add", "edit", "modify", "move", "rename", "run", "exec", "execute", "install", "upload",
	"transfer", "pay", "publish", "push", "commit", "merge", "close", "open", "start", "stop",
	"kill", "drop", "reset", "clear", "reply", "forward", "share", "invite", "grant", "revoke", "schedule", "cancel")

// Words in a tool's name that say it handles private data. Over-labelling here is the safe
// direction: the label only adds a Rule-of-Two bit.
var sensitiveWords = set("secret", "secrets", "credential", "credentials", "password", "passwords",
	"passwd", "token", "tokens", "apikey", "ssh", "keychain", "vault", "balance", "iban",
	"payment", "payments", "invoice", "salary", "payroll", "ssn", "private", "pii", "medical", "health")

var sensitiveInDescription = regexp.MustCompile(`(?i)\b(passwords?|credentials?|secrets?|api[ _-]?keys?|private keys?|access tokens?|bank account|credit card|social security)\b`)

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// words splits a tool name on separators and case changes: "getFileContents" and
// "get-file.contents" both give get, file, contents.
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(runes[i-1]) ||
			unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1])):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

func boolIs(p *bool, want bool) bool { return p != nil && *p == want }

// For returns one suggestion per tool in the record, sorted by tool name.
func For(rec baseline.ServerRecord) []Suggestion {
	out := make([]Suggestion, 0, len(rec.Tools))
	for name, tr := range rec.Tools {
		out = append(out, suggest(name, tr.Baseline))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

func suggest(name string, snap baseline.Snapshot) Suggestion {
	s := Suggestion{Tool: name}
	ws := words(name)
	ann := snap.Annotations

	sensitive := false
	for _, w := range ws {
		if sensitiveWords[w] {
			sensitive = true
			s.Reasons = append(s.Reasons, "sensitive: the name contains \""+w+"\"")
			break
		}
	}
	if !sensitive && sensitiveInDescription.MatchString(snap.Description) {
		sensitive = true
		s.Reasons = append(s.Reasons, "sensitive: the description mentions private data (it can add this label, never remove one)")
	}

	readVerb := len(ws) > 0 && readVerbs[ws[0]]
	actWord := ""
	for _, w := range ws {
		if actVerbs[w] {
			actWord = w
			break
		}
	}
	switch {
	case !readVerb:
		s.Reasons = append(s.Reasons, "not read_only: the name does not start with a reading verb, so it is treated as acting")
	case actWord != "":
		s.Reasons = append(s.Reasons, "not read_only: the name starts with a reading verb but also contains \""+actWord+"\"")
	case boolIs(ann.DestructiveHint, true):
		s.Reasons = append(s.Reasons, "not read_only: the server marks the tool destructive")
	case !boolIs(ann.ReadOnlyHint, true):
		s.Reasons = append(s.Reasons, "not read_only: the name reads, but the server does not say readOnlyHint=true; confirm by hand and add read_only yourself")
	default:
		s.Labels = append(s.Labels, config.LabelReadOnly)
		s.Reasons = append(s.Reasons, "read_only: the name starts with \""+ws[0]+"\" and the server says readOnlyHint=true")
	}

	if sensitive {
		s.Labels = append(s.Labels, config.LabelSensitive)
	}
	if len(s.Labels) == 0 {
		s.Reasons = append(s.Reasons, "left at the server default (untrusted input, acts): nothing here changes it")
		return s
	}

	s.Labels = append([]string{config.LabelUntrusted}, s.Labels...)
	s.Reasons = append(s.Reasons, "untrusted: always suggested; drop it by hand only for a tool whose results can never contain text written by someone else")
	if boolIs(ann.OpenWorldHint, true) {
		s.Reasons = append(s.Reasons, "untrusted is also what the server's openWorldHint=true says")
	}
	sort.Strings(s.Labels)
	return s
}

// Fragment builds the config fragment for the suggestions that change something. Tool names
// are escaped so that a name containing a glob character matches only itself.
func Fragment(server string, suggestions []Suggestion) map[string]map[string]map[string][]string {
	entries := map[string][]string{}
	for _, s := range suggestions {
		if len(s.Labels) > 0 {
			entries[escapeGlob(s.Tool)] = s.Labels
		}
	}
	return map[string]map[string]map[string][]string{"mcp_tool_labels": {server: entries}}
}

func escapeGlob(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '*', '?', '[', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
