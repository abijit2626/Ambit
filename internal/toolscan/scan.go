// Package toolscan implements detector D5: instruction-shaped language, role
// assertions, and cross-server references in MCP tool metadata.
//
// The premise is that a tool description is data the model reads as if it were
// instruction. A poisoned description does not need to exploit anything; it only
// needs to be read. So this scans the text a server advertises, at the moment it
// advertises it, before any call has been made.
//
// What this package is not: a prompt-injection classifier. docs/06-prior-art.md
// non-goal 4 rules that out as a primary defense, and nothing here is a boundary
// — a finding is an alert, never a block. The patterns are a **first draft** whose
// false-positive rate is measured in M1 against the cohort's real servers, which
// is why every rule carries a stable id: a rule that fires on a legitimate
// credentials-management server gets retired on evidence rather than argued about.
//
// The three-category decomposition — concealed instructions, sensitive file
// references, sensitive actions — follows lasso-security/mcp-gateway's
// ToolAnalyzer (MIT), which sorts patterns this way and scans parameter
// descriptions as well as the tool description. See
// docs/08-mcp-interpose-decision.md on what was taken and what was not. The
// patterns themselves are ours and are deliberately narrower.
package toolscan

import (
	"regexp"
	"sort"
	"strings"
)

// Finding classes. These are the SIEM-visible vocabulary: they cross to Wazuh in
// cleartext because they carry the security meaning, while the matched text does
// not cross at all.
const (
	ClassHiddenInstruction = "hidden_instruction"
	ClassRoleAssertion     = "role_assertion"
	ClassSensitiveFileRef  = "sensitive_file_ref"
	ClassSensitiveAction   = "sensitive_action"
	ClassCrossServerRef    = "cross_server_ref"
)

// Finding is one rule hit.
//
// It deliberately carries no matched text. The matched string comes from an
// untrusted server, and the rule id plus the field is enough to triage: an
// analyst reading "hidden.ignore_previous in description" knows exactly what
// fired. The description itself is kept in the endpoint's baseline store, where
// an investigator can read it without it having travelled to a SIEM or to an
// external monitoring firm.
type Finding struct {
	RuleID string `json:"rule_id"`
	Class  string `json:"class"`
	Field  string `json:"field"`
}

type rule struct {
	id    string
	class string
	re    *regexp.Regexp
}

// rules is the pattern table. Bounded `.{0,N}` spans rather than unbounded ones
// keep RE2 cheap on a large schema and keep a match local enough to mean
// something.
var rules = []rule{
	// Concealed or overriding instructions: the s1ngularity and tool-poisoning
	// shape, where metadata tells the model to do something the user did not ask
	// for and not to mention it.
	{"hidden.ignore_previous", ClassHiddenInstruction, regexp.MustCompile(`(?is)\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?|context)`)},
	{"hidden.conceal_from_user", ClassHiddenInstruction, regexp.MustCompile(`(?is)\bdo\s+not\s+(tell|show|mention|inform|reveal|display|report)\b.{0,60}\b(user|human|operator|caller)\b`)},
	{"hidden.pseudo_tag", ClassHiddenInstruction, regexp.MustCompile(`(?is)<\s*/?\s*(important|system|secret|hidden|instructions?)\s*>`)},
	{"hidden.precondition_other_tools", ClassHiddenInstruction, regexp.MustCompile(`(?is)\b(before|prior\s+to|after)\s+(using|calling|invoking|running)\s+(any\s+)?(other\s+)?tools?\b`)},
	{"hidden.imperative_obligation", ClassHiddenInstruction, regexp.MustCompile(`(?is)\byou\s+(must|should|need\s+to|are\s+required\s+to|have\s+to)\b`)},
	{"hidden.piggyback_action", ClassHiddenInstruction, regexp.MustCompile(`(?is)\b(also|additionally|in\s+addition)\b.{0,40}\b(execute|run|read|send|include|append|upload|fetch)\b`)},
	{"hidden.do_not_summarize", ClassHiddenInstruction, regexp.MustCompile(`(?is)\bdo\s+not\s+(summarize|paraphrase|modify|alter)\b`)},

	// Role assertions: metadata claiming a position in the conversation it does
	// not have.
	{"role.assume_role", ClassRoleAssertion, regexp.MustCompile(`(?is)\b(you\s+are\s+(now\s+)?(a|an|the)\b|act\s+as\b|assume\s+the\s+role\s+of\b|pretend\s+to\s+be\b)`)},
	{"role.chat_turn_marker", ClassRoleAssertion, regexp.MustCompile(`(?im)^\s*(system|assistant|user|human)\s*:`)},
	{"role.as_an_ai", ClassRoleAssertion, regexp.MustCompile(`(?is)\bas\s+an?\s+(ai|assistant|language\s+model)\b`)},

	// Sensitive file references. Expect false positives here from servers whose
	// legitimate job is credential or secret management; that is what M1 measures.
	{"sensitive_file.ssh", ClassSensitiveFileRef, regexp.MustCompile(`(?i)(\.ssh\b|\bid_rsa\b|\bid_ed25519\b|\bauthorized_keys\b|\bknown_hosts\b)`)},
	{"sensitive_file.env", ClassSensitiveFileRef, regexp.MustCompile(`(?i)(\.env\b|\.envrc\b|\benvironment\s+file\b)`)},
	{"sensitive_file.cloud_creds", ClassSensitiveFileRef, regexp.MustCompile(`(?i)(\.aws\b|\.kube\b|\.docker/config|\baws_secret\b|\baccess[_-]?key[_-]?id\b|\bservice[_-]?account[_-]?key\b)`)},
	{"sensitive_file.token_store", ClassSensitiveFileRef, regexp.MustCompile(`(?i)(\.npmrc\b|\.netrc\b|\.git-credentials\b|\bkeychain\b|\bcredentials\s+file\b)`)},
	{"sensitive_file.secret_word", ClassSensitiveFileRef, regexp.MustCompile(`(?i)(\bapi[_ -]?keys?\b|\bsecret[_ -]?keys?\b|\bpasswords?\b|\bcredentials?\b|\bprivate[_ -]?key\b)`)},

	// Sensitive actions: the second half of an exfiltration instruction.
	{"sensitive_action.http_post", ClassSensitiveAction, regexp.MustCompile(`(?is)\b(post|put|send|upload|transmit|forward|exfiltrate)\b.{0,40}\bhttps?://`)},
	{"sensitive_action.http_client", ClassSensitiveAction, regexp.MustCompile(`(?i)\b(curl|wget|nc|netcat)\b.{0,40}(https?://|\bhttp\b)`)},
	{"sensitive_action.encode", ClassSensitiveAction, regexp.MustCompile(`(?i)\b(base64|hex[_ -]?encode|rot13)\b`)},
	{"sensitive_action.destructive_shell", ClassSensitiveAction, regexp.MustCompile(`(?i)(\brm\s+-[a-z]*r[a-z]*f?\b|\bsudo\b|\bchmod\s+777\b|\bdd\s+if=)`)},
	{"sensitive_action.search_for_secrets", ClassSensitiveAction, regexp.MustCompile(`(?is)\b(search|scan|look|grep|find)\b.{0,40}\b(for)\b.{0,40}\b(password|secret|api[_ -]?key|token|credential)`)},
}

// mcpToolRef matches Claude Code's MCP tool naming. A description naming another
// server's tool is the cross-server shadowing signature: one server's metadata
// altering the model's behavior toward a different server's tools.
var mcpToolRef = regexp.MustCompile(`mcp__([A-Za-z0-9_.-]+)__([A-Za-z0-9_.-]+)`)

// Scanner scans metadata for one server.
type Scanner struct {
	// self is the server whose metadata is being scanned. A server naming its
	// own tools is ordinary; naming another server's is not.
	self string
	// others are sibling server names from operator configuration. Matching on a
	// name shorter than minNameLen is skipped: a server called "db" would match
	// half the English language.
	others []string
}

const minNameLen = 4

// New builds a scanner for one server. others may be nil; cross-server detection
// still works through the mcp__server__tool form, which needs no configuration.
func New(self string, others []string) *Scanner {
	s := &Scanner{self: strings.ToLower(self)}
	for _, o := range others {
		o = strings.ToLower(strings.TrimSpace(o))
		if o == "" || o == s.self || len(o) < minNameLen {
			continue
		}
		s.others = append(s.others, o)
	}
	sort.Strings(s.others)
	return s
}

// ScanText runs every rule over one field's text.
func (s *Scanner) ScanText(field, text string) []Finding {
	if text == "" {
		return nil
	}
	var out []Finding
	for _, r := range rules {
		if r.re.MatchString(text) {
			out = append(out, Finding{RuleID: r.id, Class: r.class, Field: field})
		}
	}
	out = append(out, s.crossServer(field, text)...)
	return out
}

// ScanFields runs every rule over each named field, in a stable field order so
// two scans of the same tool produce identical output.
func (s *Scanner) ScanFields(fields map[string]string) []Finding {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []Finding
	for _, name := range names {
		out = append(out, s.ScanText(name, fields[name])...)
	}
	return out
}

func (s *Scanner) crossServer(field, text string) []Finding {
	var out []Finding
	seen := map[string]bool{}

	for _, m := range mcpToolRef.FindAllStringSubmatch(text, -1) {
		if strings.EqualFold(m[1], s.self) {
			continue
		}
		if seen["prefix"] {
			continue
		}
		seen["prefix"] = true
		out = append(out, Finding{RuleID: "cross.mcp_tool_ref", Class: ClassCrossServerRef, Field: field})
	}

	lower := strings.ToLower(text)
	for _, other := range s.others {
		if strings.Contains(lower, other) && !seen["name"] {
			seen["name"] = true
			out = append(out, Finding{RuleID: "cross.sibling_server_name", Class: ClassCrossServerRef, Field: field})
		}
	}
	return out
}

// Classes reduces findings to the sorted, deduplicated class list that crosses to
// Wazuh.
func Classes(findings []Finding) []string {
	if len(findings) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, f := range findings {
		set[f.Class] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// RuleIDs reduces findings to the sorted, deduplicated rule list. Rule ids stay
// in the local spool: they are how a false-positive rate is attributed to a
// specific pattern during M1 tuning.
func RuleIDs(findings []Finding) []string {
	if len(findings) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, f := range findings {
		set[f.RuleID] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
