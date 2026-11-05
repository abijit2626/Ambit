package classify

import (
	"path"
	"strings"
)

// A here-document's body follows the line that holds its operator, and what the body is depends on
// the command that reads it, as it does for bash:
//
//   - a shell (bash, sh, ssh host, su) runs it, so its lines are commands
//   - an interpreter (python3 -, node, ruby) runs it as code, read like python -c's
//   - a command that only reads data (cat, tee, psql, git commit -F -) does not run it at all:
//     cat > README.md <<EOF writes text, and a curl example in that text contacts nothing
//
// Before here-documents were read, every body line was split out and classified as a command, so a
// README written with a curl example was network, and code piped into python3 was other. A body is
// only taken for data when its reader is a known data reader; any other reader keeps the old
// reading, as commands, so the change can only make a body count for less where bash agrees.
//
// A body written to a file that the same command then runs, as in cat > x.sh <<EOF ... EOF; bash
// x.sh, is classified as that script, so writing a script and running it is not hidden by the
// write.

type docKind int

const (
	docCommands docKind = iota
	docCode
	docData
)

type heredoc struct {
	delim string
	strip bool // <<- also allows tabs before the terminator
	body  string

	kind    docKind
	lang    inlineLanguage // for docCode
	written string         // the file a data reader writes the body to, if any
}

// heredocMark stands in for a here-document's operator in the outer command, so the segment that
// reads it can be found after splitSegments.
const heredocMark = "\x00heredoc\x00"

// splitHeredocs takes a command's here-documents out of it: outer is the command with every body and
// terminator line removed and every operator replaced by heredocMark, and docs are the bodies in
// order. A command without one comes back as it is, with no docs.
//
// The scan follows bash where it decides what is a body: quotes, a backslash, a comment and
// arithmetic ($((1<<2)), ((x<<1))) hide "<<"; "<<<" is a here-string; bodies start on the line after
// their operators, one after another, and run to a line that is the delimiter alone, or to the end of
// the command. The scan is linear: a body is read once and skipped.
func splitHeredocs(command string) (outer string, docs []heredoc) {
	if !strings.Contains(command, "<<") {
		return command, nil
	}
	var b strings.Builder
	var pending []int
	n := len(command)
	copied := 0
	atWordStart := true
	for i := 0; i < n; {
		c := command[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			j := closingQuote(command, i)
			if j < 0 {
				i = n
				continue
			}
			i = j + 1
			atWordStart = false
			continue
		case c == '\\':
			i = min(i+2, n)
			atWordStart = false
			continue
		case c == '#' && atWordStart:
			// A comment runs to the end of the line, and a "<<" in it is not an operator.
			if j := strings.IndexByte(command[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = n
			}
			continue
		case c == '(' && i+1 < n && command[i+1] == '(':
			// Arithmetic, where "<<" is a shift.
			i = skipArithmetic(command, i)
			atWordStart = false
			continue
		case c == '<' && i+1 < n && command[i+1] == '<' && (i+2 >= n || command[i+2] != '<'):
			delim, strip, end := heredocDelimiter(command, i+2)
			if delim == "" {
				i += 2
				continue
			}
			b.WriteString(command[copied:i])
			b.WriteString(heredocMark)
			copied = end
			docs = append(docs, heredoc{delim: delim, strip: strip})
			pending = append(pending, len(docs)-1)
			i = end
			atWordStart = false
			continue
		case c == '<' && i+2 < n && command[i+1] == '<' && command[i+2] == '<':
			i += 3
			continue
		case c == '\n' && len(pending) > 0:
			b.WriteString(command[copied : i+1])
			start := i + 1
			for _, k := range pending {
				body, next := heredocBody(command, start, docs[k].delim, docs[k].strip)
				docs[k].body = body
				start = next
			}
			pending = pending[:0]
			copied = start
			i = start
			atWordStart = true
			continue
		}
		atWordStart = c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')'
		i++
	}
	if len(docs) == 0 {
		return command, nil
	}
	b.WriteString(command[copied:])
	outer = b.String()
	readers(outer, docs)
	return outer, docs
}

// heredocDelimiter reads the delimiter word after "<<" at i: an optional "-", blanks, then a word
// whose quotes and backslashes are removed, as bash does. It returns where the word ends.
func heredocDelimiter(command string, i int) (delim string, strip bool, end int) {
	n := len(command)
	if i < n && command[i] == '-' {
		strip = true
		i++
	}
	for i < n && (command[i] == ' ' || command[i] == '\t') {
		i++
	}
	var w strings.Builder
	for i < n {
		c := command[i]
		if strings.IndexByte(" \t\n;&|<>()", c) >= 0 {
			break
		}
		switch c {
		case '\'', '"':
			j := closingQuote(command, i)
			if j < 0 {
				return "", false, i
			}
			w.WriteString(command[i+1 : j])
			i = j + 1
			continue
		case '\\':
			if i+1 < n {
				w.WriteByte(command[i+1])
			}
			i = min(i+2, n)
			continue
		}
		w.WriteByte(c)
		i++
	}
	return w.String(), strip, i
}

// heredocBody reads the body that starts at start: lines up to one that is the delimiter alone, after
// leading tabs when strip is set, or to the end of the command. next is where the following text,
// or the next pending body, starts.
func heredocBody(command string, start int, delim string, strip bool) (body string, next int) {
	for ls := start; ls < len(command); {
		le := strings.IndexByte(command[ls:], '\n')
		if le < 0 {
			le = len(command)
		} else {
			le += ls
		}
		line := command[ls:le]
		if strip {
			line = strings.TrimLeft(line, "\t")
		}
		if line == delim {
			return command[start:ls], min(le+1, len(command))
		}
		ls = le + 1
	}
	return command[min(start, len(command)):], len(command)
}

// skipArithmetic skips "((" to its matching "))", or to the end.
func skipArithmetic(command string, i int) int {
	depth := 0
	for ; i < len(command); i++ {
		switch command[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(command)
}

// dataReaders read a here-document as data: they print, store, transform or send it, and run none
// of it. A reader not listed here keeps the old reading of its body, as commands. Some that look
// like data readers are left out because they can run what they read: kubectl exec -i pod -- sh,
// psql's \! and sqlite3's .system, crontab's jobs.
var dataReaders = map[string]bool{
	"cat": true, "tee": true, "dd": true, "head": true, "tail": true, "wc": true, "sort": true,
	"uniq": true, "tr": true, "cut": true, "grep": true, "rg": true, "base64": true, "xxd": true,
	"gzip": true, "jq": true, "yq": true, "column": true, "fold": true, "rev": true, "diff": true,
	"patch": true, "read": true, "mapfile": true, "readarray": true, "envsubst": true, "git": true,
	"gh": true, "curl": true, "openssl": true, "gpg": true,
}

// readers sets each here-document's kind from the segment of outer that holds its operator.
func readers(outer string, docs []heredoc) {
	k := 0
	for _, seg := range splitSegments(outer) {
		marks := strings.Count(seg, heredocMark)
		if marks == 0 {
			continue
		}
		toks := tokenize(strings.ReplaceAll(seg, heredocMark, " "))
		i := skipPrefix(toks)
		tool, args := "", []string(nil)
		if i < len(toks) {
			tool, args = baseName(toks[i]), toks[i+1:]
		}
		for m := 0; m < marks && k < len(docs); m, k = m+1, k+1 {
			switch lang, isCode := inlineLanguageOf(tool); {
			case isCode:
				docs[k].kind, docs[k].lang = docCode, lang
			case dataReaders[tool]:
				docs[k].kind = docData
				docs[k].written = writtenFile(tool, args)
			default:
				docs[k].kind = docCommands
			}
		}
	}
}

// writtenFile is the file a data reader writes its input to: the target of "> f" or ">> f", or tee's
// first file.
func writtenFile(tool string, args []string) string {
	for i, a := range args {
		a = stripQuotes(a)
		if op, rest, ok := redirectWord(a); ok && op == '>' {
			if rest != "" {
				return rest
			}
			if i+1 < len(args) {
				return stripQuotes(args[i+1])
			}
		}
	}
	if tool == "tee" {
		for _, a := range args {
			if a = stripQuotes(a); a != "" && a[0] != '-' {
				return a
			}
		}
	}
	return ""
}

// classifyHeredocs classifies a command that has here-documents: the outer command as usual, each
// body by what reads it, and each body written to a file that the command then runs, as that script.
func classifyHeredocs(outer string, docs []heredoc, depth int) string {
	best := classifyCommand(strings.ReplaceAll(outer, heredocMark, " "), depth)
	raise := func(c string) {
		if severity(c) > severity(best) {
			best = c
		}
	}
	written := map[string]string{}
	for _, d := range docs {
		switch d.kind {
		case docCommands:
			raise(classifyCommand(d.body, depth+1))
		case docCode:
			raise(codeClass(d.lang, d.body, depth+1))
		case docData:
			if d.written != "" {
				written[path.Clean(d.written)] = d.body
			}
		}
	}
	for _, run := range ScriptsRun(strings.ReplaceAll(outer, heredocMark, " ")) {
		if body, ok := written[path.Clean(run.Path)]; ok {
			if c, ok := scriptClass(run.Path, run.Runner, body, depth+1); ok {
				raise(c)
			}
		}
	}
	return best
}

// codeClass is the class of code in an interpreter's language: network when it names a network API
// of the language, and at least the class of every command it launches.
func codeClass(lang inlineLanguage, code string, depth int) string {
	best := ClassOther
	if lang.api.MatchString(code) {
		best = ClassNetwork
	}
	if depth < maxUnwrapDepth {
		for _, cmd := range spawnedCommands(lang, code) {
			if c := classifyCommand(cmd, depth+1); severity(c) > severity(best) {
				best = c
			}
		}
	}
	return best
}

// ScriptRun is a script a command runs, as its path is written in the command, and the shell or
// interpreter that runs it, if one is named.
type ScriptRun struct {
	Path   string
	Runner string
}

var shellRunners = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "fish": true, "source": true, ".": true}

// ScriptsRun is each script file a command runs: the file a shell or interpreter is given
// ("bash deploy.sh", "python3 -u tools/x.py", "source env.sh") and a command named by a path
// ("./deploy.sh", "/tmp/x.py"). Code given inline (-c, -e) and modules (-m) are not files.
func ScriptsRun(command string) []ScriptRun {
	var out []ScriptRun
	for _, seg := range splitSegments(command) {
		toks := tokenize(seg)
		i := skipPrefix(toks)
		if i >= len(toks) {
			continue
		}
		word := stripQuotes(toks[i])
		tool := baseName(word)
		_, interp := inlineLanguageOf(tool)
		switch {
		case shellRunners[tool] || interp:
			if p := scriptOperand(tool, toks[i+1:]); p != "" {
				out = append(out, ScriptRun{Path: p, Runner: tool})
			}
		case strings.ContainsRune(word, '/'):
			out = append(out, ScriptRun{Path: word})
		}
	}
	return out
}

// scriptOperand is the script file a shell or interpreter is given: its first word that is not an
// option, or "" when it runs inline code or a module instead.
func scriptOperand(tool string, args []string) string {
	for i := 0; i < len(args); i++ {
		a := stripQuotes(args[i])
		switch {
		case a == "-c" || a == "-e" || a == "-E" || a == "-r" || a == "-m" || a == "-p" || a == "--eval" || a == "--print" || shellCFlag.MatchString(a):
			return ""
		case a == "-" || a == "--":
			continue
		case strings.HasPrefix(a, "-"):
			if isPython(tool) && (a == "-W" || a == "-X") {
				i++
			}
			continue
		case (tool == "deno" || tool == "bun") && (a == "run" || a == "eval"):
			if a == "eval" {
				return ""
			}
			continue
		}
		return a
	}
	return ""
}

// ScriptClass is the class of a script's content, when path or its first line says what runs it: a
// shell script's commands, or an interpreter's code as codeClass reads it. ok is false for a file
// that is not a script ambit can read, such as data or a binary.
func ScriptClass(scriptPath, content string) (class string, ok bool) {
	return scriptClass(scriptPath, "", content, 0)
}

func scriptClass(scriptPath, runner, content string, depth int) (string, bool) {
	kind := runner
	if kind == "" {
		kind = scriptKind(scriptPath, content)
	}
	switch {
	case kind == "":
		return "", false
	case shellRunners[kind] || kind == "pwsh" || kind == "powershell":
		if depth >= maxUnwrapDepth {
			return "", false
		}
		return classifyCommand(content, depth), true
	}
	if lang, ok := inlineLanguageOf(kind); ok {
		return codeClass(lang, content, depth), true
	}
	return "", false
}

// scriptKind names what runs a script: its shebang's program, or else its extension's.
func scriptKind(scriptPath, content string) string {
	if first, _, _ := strings.Cut(content, "\n"); strings.HasPrefix(first, "#!") {
		f := strings.Fields(first[2:])
		if len(f) > 0 {
			prog := baseName(f[0])
			if prog == "env" {
				for _, a := range f[1:] {
					if !strings.HasPrefix(a, "-") {
						prog = baseName(a)
						break
					}
				}
			}
			if shellRunners[prog] {
				return prog
			}
			if _, ok := inlineLanguageOf(prog); ok {
				return prog
			}
		}
	}
	switch strings.ToLower(path.Ext(scriptPath)) {
	case ".sh", ".bash", ".zsh", ".ksh":
		return "sh"
	case ".ps1":
		return "pwsh"
	case ".py":
		return "python3"
	case ".js", ".mjs", ".cjs", ".ts", ".mts":
		return "node"
	case ".rb":
		return "ruby"
	case ".pl", ".pm":
		return "perl"
	case ".php":
		return "php"
	}
	return ""
}

// WrittenFile is a file a command writes from a here-document, with the content it writes.
type WrittenFile struct {
	Path    string
	Content string
}

// FilesWritten is each file a command writes from a here-document, as in cat > deploy.sh <<'EOF'.
func FilesWritten(command string) []WrittenFile {
	_, docs := splitHeredocs(command)
	var out []WrittenFile
	for _, d := range docs {
		if d.kind == docData && d.written != "" {
			out = append(out, WrittenFile{Path: d.written, Content: d.body})
		}
	}
	return out
}

// Max is whichever of two classes says more about what a command can do: publish over vcs_write over
// network over filesystem over other over read_only.
func Max(a, b string) string {
	if severity(b) > severity(a) {
		return b
	}
	return a
}
