package classify

import (
	"regexp"
	"strings"
)

// maxWriteTargets bounds how many files one command contributes, as maxCredentialPaths does.
const maxWriteTargets = 16

// maxShellPath is PATH_MAX on Linux; a cd past it fails.
const maxShellPath = 4096

// A WriteTarget is a file a command writes. Word is the file as the command names it in the write;
// Path is Word joined to the directory an earlier cd in the command went to, still to be resolved by
// Zoner.ShellPath. Without a cd they are the same.
type WriteTarget struct {
	Word string
	Path string
}

// WriteTargets is each file a Bash or PowerShell command writes through a redirect (">", ">>", "2>",
// "&>", ">|") or through tee: "echo x >> ~/.bashrc" writes ~/.bashrc, and "echo k | sudo tee -a
// /etc/hosts" writes /etc/hosts. A relative target named after a cd earlier in the command is joined
// to where that cd went, so "cd /etc && echo x > hosts" writes /etc/hosts. A cd in a subshell, a
// pipeline or the background moves nothing after it, and the command after "cd x ||" runs where the
// cd started. After a cd to a place the command does not spell out, as in cd "$dir", a relative
// target is left out, as is a target the shell would expand to something the command does not spell
// out, as in "> $OUT".
//
// The commands inside a command substitution, "$(cmd)" or `cmd`, and a process substitution,
// "<(cmd)" or ">(cmd)", are read as commands of their own, inside double quotes too, where the shell
// still runs them. A comparison in "[[ ]]" or "(( ))" writes nothing.
//
// The command is read as bash reads it, a backslash escaping the byte after it, and, when it holds a
// backslash or a backtick, also as PowerShell reads it, where a backtick escapes and a backslash is a
// path separator. A quote one shell takes as escaped, the other takes as opening a string, so a
// write either one would make is found whichever shell runs the command.
//
// A device is not a file the command keeps, so /dev/null, /dev/stderr, /dev/tcp/... and NUL are left
// out. A here-document read as commands is read like the rest of the command; one read as data or
// code writes nothing.
func WriteTargets(command string) []WriteTarget {
	if !mayWrite(command) {
		return nil
	}
	r := writeReader{seen: map[string]bool{}}
	// A NUL stands in for each here-document's operator: it ends a word, and a word an open quote
	// carries it into names no file, since no file name holds a NUL.
	outer, docs := splitHeredocs(command)
	outer = strings.ReplaceAll(outer, heredocMark, "\x00")
	escapes := []byte{'\\'}
	if strings.ContainsAny(command, "\\`") {
		escapes = append(escapes, '`')
	}
	for _, esc := range escapes {
		r.esc = esc
		r.read(lexShell(outer, esc), 0, place{})
		for _, d := range docs {
			if d.kind == docCommands {
				r.read(lexShell(d.body, esc), 1, place{})
			}
		}
	}
	return r.out
}

// writeWords are the words a command without a ">" needs for WriteTargets to find a write in it: tee,
// or a PowerShell whose -EncodedCommand can hide a ">" in base64.
var writeWords = []string{"tee", "powershell", "pwsh"}

// mayWrite reports whether a command can hold a write WriteTargets reads, so that most commands,
// which hold none, are not read for one.
func mayWrite(command string) bool {
	return strings.IndexByte(command, '>') >= 0 || newFoldText(command).mayHold(writeWords)
}

// A place is where the commands of a command run: dir is where a cd went, "" for where the command
// started, and lost is set after a cd to a place the command does not spell out.
type place struct {
	dir  string
	lost bool
}

type writeReader struct {
	esc  byte // the byte that escapes the next: '\\' for bash, '`' for PowerShell
	out  []WriteTarget
	seen map[string]bool
}

func (r *writeReader) full() bool { return len(r.out) >= maxWriteTargets }

// read records the writes of the commands in items, run from at.
func (r *writeReader) read(items []shellItem, depth int, at place) {
	cur := at
	var outer []place   // where each open subshell's parent is, to return to when it closes
	var fallback *place // where the command after "cd x ||" runs: where the cd started
	prevOp := ""
	for k := 0; k < len(items) && !r.full(); {
		if op := items[k].op; op != "" {
			switch op {
			case "(":
				outer = append(outer, cur)
			case ")":
				if n := len(outer); n > 0 {
					cur, outer = outer[n-1], outer[:n-1]
				}
			}
			prevOp = op
			k++
			continue
		}
		end := k
		for end < len(items) && items[end].op == "" {
			end++
		}
		nextOp := ""
		if end < len(items) {
			nextOp = items[end].op
		}
		here := cur
		if fallback != nil {
			here, fallback = *fallback, nil
		}
		// A cd in a pipeline or the background runs in a subshell of its own and moves nothing after it.
		if to, ok := r.command(items[k:end], depth, here); ok && prevOp != "|" && nextOp != "|" && nextOp != "&" {
			if nextOp == "||" {
				from := here
				fallback = &from
			}
			cur = to
		}
		prevOp = ""
		k = end
	}
}

// command records the writes of one simple command run from here, and reports where it moves to if it
// is a cd, pushd or popd.
func (r *writeReader) command(words []shellItem, depth int, here place) (to place, isCd bool) {
	tokens := make([]string, len(words))
	for k, w := range words {
		tokens[k] = w.word
		for _, sub := range w.subs {
			// A substitution runs in a subshell: it starts here, and a cd in it moves nothing out here.
			r.read(sub, depth, here)
		}
	}
	add := func(w string) {
		w = stripQuotes(w)
		if w == "" || w == "-" || strings.IndexByte(w, 0) >= 0 || isDevice(w) || !resolvable(w) || r.full() {
			return
		}
		p := w
		if !anchored(w) {
			if here.lost {
				return
			}
			if here.dir != "" {
				p = here.dir + "/" + w
			}
		}
		if !r.seen[p] {
			r.seen[p] = true
			r.out = append(r.out, WriteTarget{Word: w, Path: p})
		}
	}
	i := skipPrefix(tokens)
	tool := ""
	if i < len(tokens) {
		tool = baseName(tokens[i])
	}
	// Every operand of tee is a file it writes. "--" ends its options; an input redirect and the word
	// it reads are not operands.
	pending, input, operands, inTest := false, false, false, false
	for k, tok := range tokens {
		if pending {
			pending = false
			add(tok)
			continue
		}
		// In "[[ a > b ]]", ">" compares two strings.
		if t := stripQuotes(tok); t == "[[" || t == "]]" {
			inTest = t == "[["
			continue
		}
		if inTest {
			continue
		}
		if op, target, ok := redirect(tok, r.esc); ok {
			if op == '>' {
				if target == "" {
					pending = true
				} else {
					add(target)
				}
			} else if target == "" {
				input = true
			}
			continue
		}
		if tool != "tee" || k <= i {
			continue
		}
		switch a := stripQuotes(tok); {
		case input:
			input = false
		case operands || !strings.HasPrefix(a, "-"):
			add(tok)
		case a == "--":
			operands = true
		}
	}
	if depth < maxUnwrapDepth && i < len(tokens) {
		if inner, ok := innerCommand(tool, tokens[i+1:]); ok {
			r.read(lexShell(inner, r.esc), depth+1, here)
		}
	}
	switch tool {
	case "cd", "pushd":
		return cdPlace(here, cdTarget(tokens[i+1:])), true
	case "popd":
		return place{lost: true}, true
	}
	return here, false
}

// cdPlace is where a cd from here to the directory to goes.
func cdPlace(here place, to string) place {
	switch {
	case to == "" || !resolvable(to):
		return place{lost: true}
	case anchored(to):
		return place{dir: to}
	case here.lost:
		return here
	}
	if here.dir != "" {
		to = here.dir + "/" + to
	}
	// A path longer than any a system opens is not followed: joining a long chain of relative cds
	// would copy the directory once per cd.
	return place{dir: to, lost: len(to) > maxShellPath}
}

// cdTarget is where cd or pushd with these arguments goes, as written: "~" for cd alone, and "" for
// "cd -", the last directory, which the command does not say.
func cdTarget(args []string) string {
	for _, a := range args {
		switch a = stripQuotes(a); {
		case a == "-":
			return ""
		case strings.HasPrefix(a, "-"):
			// -L, -P, -e, -@, and "--" before the directory.
		default:
			if _, _, ok := redirect(a, 0); !ok {
				return a
			}
		}
	}
	return "~"
}

// A shellItem is an operator, or a word as the command writes it, quotes and escapes kept, with each
// substitution in it replaced by substMark and its commands in subs.
type shellItem struct {
	op   string // ";", "&&", "||", "|", "&", "(", ")"; "" for a word
	word string
	subs [][]shellItem
}

// substMark stands in for a substitution in a word. It holds a "$", so the word is not resolvable.
const substMark = "$()"

// lexShell splits a command into words and operators as a shell does, esc being the byte that escapes
// the one after it outside single quotes. A redirect stays part of its word ("2>&1", ">f"); a quote
// left open runs to the end of the command, which the shell would refuse to run. It reads each byte
// once, substitutions included.
func lexShell(s string, esc byte) []shellItem {
	l := shellLexer{s: s, esc: esc}
	return l.items(0)
}

type shellLexer struct {
	s   string
	esc byte
	i   int
}

// items lexes from l.i to closer: ')' for the end of "$(" or "<(", '`' for the end of a backtick
// substitution, and 0 for the end of the command. l.i is left after the closer.
func (l *shellLexer) items(closer byte) []shellItem {
	var items []shellItem
	var w strings.Builder
	var subs [][]shellItem
	inWord := false
	var last byte // the last byte of the word so far
	flush := func() {
		if inWord {
			items = append(items, shellItem{word: w.String(), subs: subs})
			w.Reset()
			subs, inWord, last = nil, false, 0
		}
	}
	op := func(o string) {
		flush()
		items = append(items, shellItem{op: o})
	}
	write := func(s string) {
		if s != "" {
			w.WriteString(s)
			last, inWord = s[len(s)-1], true
		}
	}
	parens := 0 // subshells opened inside this substitution
	s := l.s
	for l.i < len(s) {
		c, i := s[l.i], l.i
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		l.i++
		switch {
		case c == l.esc:
			if next == '\n' {
				l.i++ // a line continuation
				continue
			}
			write(s[i:min(i+2, len(s))])
			l.i = min(i+2, len(s))
		case c == '\'':
			end := len(s)
			if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
				end = i + j + 2
			}
			write(s[i:end])
			l.i = end
		case c == '"':
			write(l.doubleQuoted(&subs))
		case c == '`' && l.esc == '\\':
			if closer == '`' {
				flush()
				return items
			}
			subs = append(subs, l.items('`'))
			write(substMark)
		case c == '$' && next == '(':
			if end, ok := arithmetic(s, i+1); ok {
				l.i = end
			} else {
				l.i = i + 2
				subs = append(subs, l.items(')'))
			}
			write(substMark)
		case (c == '<' || c == '>') && next == '(':
			l.i = i + 2
			subs = append(subs, l.items(')'))
			write(substMark)
		case c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f' || c == 0:
			flush()
		case c == '\n' || c == ';':
			op(";")
		case c == '&':
			switch {
			case next == '&':
				op("&&")
				l.i++
			case next == '>' || (inWord && (last == '>' || last == '<')):
				write("&")
			default:
				op("&")
			}
		case c == '|':
			switch {
			case inWord && last == '>':
				write("|") // ">|" overrides noclobber
			case next == '|':
				op("||")
				l.i++
			case next == '&':
				op("|")
				l.i++
			default:
				op("|")
			}
		case c == '(':
			if inWord {
				// An extglob, "!(*.log)", or a function's "()": the brackets are part of the word.
				end := closeParen(s, i+1, l.esc)
				write(s[i:end])
				l.i = end
			} else if end, ok := arithmetic(s, i); ok {
				l.i = end // "(( a > b ))" compares
			} else {
				parens++
				op("(")
			}
		case c == ')':
			if parens == 0 && closer == ')' {
				flush()
				return items
			}
			parens--
			op(")")
		default:
			write(s[i : i+1])
		}
	}
	flush()
	return items
}

// doubleQuoted reads the string whose opening quote is at l.i-1, quotes included, through its closing
// quote or the end of the command. The commands of each substitution in it are added to subs, and
// substMark stands in for it.
func (l *shellLexer) doubleQuoted(subs *[][]shellItem) string {
	s := l.s
	var b strings.Builder
	b.WriteByte('"')
	for l.i < len(s) {
		c, i := s[l.i], l.i
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		l.i++
		switch {
		case c == l.esc:
			if next != '\n' { // a line continuation is removed inside double quotes too
				b.WriteString(s[i:min(i+2, len(s))])
			}
			l.i = min(i+2, len(s))
		case c == '"':
			b.WriteByte('"')
			return b.String()
		case c == '`' && l.esc == '\\':
			*subs = append(*subs, l.items('`'))
			b.WriteString(substMark)
		case c == '$' && next == '(':
			if end, ok := arithmetic(s, i+1); ok {
				l.i = end
			} else {
				l.i = i + 2
				*subs = append(*subs, l.items(')'))
			}
			b.WriteString(substMark)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// maxArithmetic bounds how far arithmetic looks for the "))" that closes a "((": looking to the end of
// the command from every "(" of a long run of them would read the command once per bracket. Past it,
// the brackets are read as subshells, whose commands are read for writes.
const maxArithmetic = 256

// arithmetic reports whether s[i:] starts an arithmetic "((...))", and where it ends. "((cd x); y)"
// is two subshells, not arithmetic: its brackets do not close with "))".
func arithmetic(s string, i int) (end int, ok bool) {
	if !strings.HasPrefix(s[i:], "((") {
		return 0, false
	}
	depth := 0
	for j := i; j < len(s) && j < i+maxArithmetic; j++ {
		switch s[j] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return j + 1, j >= i+3 && s[j-1] == ')'
			}
		}
	}
	return 0, false
}

// closeParen is the index just past the ")" that closes an open "(" in a word before s[i], past
// quotes, escapes and nested brackets; or of the first blank or newline outside quotes, which ends
// the word first; or len(s).
func closeParen(s string, i int, esc byte) int {
	depth := 1
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f' || c == '\n' || c == 0:
			return i
		case c == esc:
			i++
		case c == '\'' || c == '"':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return len(s)
			}
			i += j + 1
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

// redirect reads a word holding a redirect outside quotes: op is '>' for one that writes (">f",
// ">>f", "2>f", "&>f", ">|f", and "x>f", a redirect run into the word before it) and '<' for one that
// reads ("<f", "0<f", "<>f"), and target is the file, or "" when it is the next word. ">&2" and "<&3"
// duplicate a descriptor, and ">(cmd)" and "<(cmd)" are process substitutions: none names a file.
// esc is the byte that escapes the next one, as lexShell takes it, or 0.
func redirect(tok string, esc byte) (op byte, target string, ok bool) {
	var quote byte
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case esc != 0 && c == esc:
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '<' || c == '>':
			if c == '>' && i > 0 && (tok[i-1] == '-' || tok[i-1] == '=') {
				// "->" and "=>" are arrows in code, not redirects.
				return 0, "", false
			}
			rest := strings.TrimLeft(tok[i:], "<>")
			if c == '>' {
				rest = strings.TrimPrefix(rest, "|")
			}
			if strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "(") {
				return 0, "", false
			}
			return c, rest, true
		}
	}
	return 0, "", false
}

var windowsDevice = map[string]bool{"nul": true, "con": true, "$null": true, "nul:": true}

func isDevice(w string) bool {
	low := strings.ToLower(strings.ReplaceAll(w, `\`, "/"))
	return strings.HasPrefix(low, "/dev/") || strings.HasPrefix(low, "/proc/self/fd/") || windowsDevice[low]
}

// homePrefix matches the ways a shell word starts at the home directory: ~, $HOME, ${HOME},
// PowerShell's $env:USERPROFILE and $env:HOME, and cmd's %USERPROFILE%.
var homePrefix = regexp.MustCompile(`(?i)^(~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|\$env:HOME|%USERPROFILE%)([/\\]|$)`)

// anchored reports whether a shell word names its file without the working directory: an absolute
// path, or one from the home directory.
func anchored(w string) bool {
	return strings.HasPrefix(w, "/") || strings.HasPrefix(w, `\`) || windowsDrive.MatchString(strings.ReplaceAll(w, `\`, "/")) ||
		homePrefix.MatchString(w)
}

// resolvable reports whether a shell word names one file that can be told without running anything:
// no variable but the home directory, no command substitution and no glob or brace expansion.
func resolvable(w string) bool {
	if m := homePrefix.FindStringIndex(w); m != nil {
		w = w[m[1]:]
	} else if strings.HasPrefix(w, "~") {
		return false // ~user is another user's home
	}
	return !strings.ContainsAny(w, "$`*?[{%")
}

// ShellPath is the file a word from a shell command names, as WriteTargets gives it: "~" and $HOME
// expanded to the home directory, and a relative path joined to the working directory. ok is false for
// a word whose file depends on anything else the shell would expand, and for a relative word when the
// working directory is not known. Zone normalizes what it is given, so a PowerShell word's backslashes
// and a word's ".." are zoned where they lead.
func (z *Zoner) ShellPath(w string) (string, bool) {
	if w == "" || !resolvable(w) {
		return "", false
	}
	if m := homePrefix.FindStringSubmatchIndex(w); m != nil {
		if z.home == "" {
			return "", false
		}
		return z.home + "/" + w[m[1]:], true
	}
	if anchored(w) {
		return w, true
	}
	if z.workdir == "" {
		return "", false
	}
	return z.workdir + "/" + w, true
}
