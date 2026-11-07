package classify

import (
	"regexp"
	"strings"
)

// maxWriteTargets bounds how many files one command contributes, as maxCredentialPaths does.
const maxWriteTargets = 16

// maxShellPath is PATH_MAX on Linux; a cd past it fails.
const maxShellPath = 4096

// WriteTargets is each file a Bash or PowerShell command writes through a redirect (">", ">>", "2>",
// "&>", ">|") or through tee, as the command names it: "echo x >> ~/.bashrc" writes ~/.bashrc, and
// "echo k | sudo tee -a /etc/hosts" writes /etc/hosts. A relative target named after a cd earlier in
// the command is joined to where that cd went, so "cd /etc && echo x > hosts" writes /etc/hosts; after
// a cd to a place the command does not spell out, as in cd "$dir", a relative target is left out.
//
// A device is not a file the command keeps, so /dev/null, /dev/stderr, /dev/tcp/... and NUL are left
// out, as is a process substitution, ">(cmd)", whose own redirects are read as the command's. A
// here-document read as commands is read like the rest of the command; one read as data or code
// writes nothing. The targets are words still to be resolved: Zoner.ShellPath expands "~" and $HOME
// and joins a relative one to the working directory.
func WriteTargets(command string) []string {
	var out []string
	seen := map[string]bool{}
	outer, docs := splitHeredocs(command)
	writeTargets(strings.ReplaceAll(outer, heredocMark, " "), 0, &out, seen)
	for _, d := range docs {
		if d.kind == docCommands && len(out) < maxWriteTargets {
			writeTargets(d.body, 1, &out, seen)
		}
	}
	return out
}

func writeTargets(command string, depth int, out *[]string, seen map[string]bool) {
	dir, lost := "", false // where a cd in the command went: "" for where it started
	for _, seg := range splitSegments(command) {
		tokens := tokenize(seg)
		i := skipPrefix(tokens)
		tool := ""
		if i < len(tokens) {
			tool = baseName(tokens[i])
		}
		add := func(w string) {
			w = stripQuotes(w)
			if w == "" || w == "-" || isDevice(w) || len(*out) >= maxWriteTargets {
				return
			}
			if !anchored(w) {
				if lost {
					return
				}
				if dir != "" {
					w = dir + "/" + w
				}
			}
			if !seen[w] {
				seen[w] = true
				*out = append(*out, w)
			}
		}
		// Every operand of tee is a file it writes. "--" ends its options; an input redirect and the word
		// it reads are not operands, and after a process substitution, whose closing bracket the
		// tokenizer drops, which words are tee's own can no longer be told.
		pending, input, operands, teeDone := false, false, false, tool != "tee"
		for k, tok := range tokens {
			if pending {
				pending = false
				add(tok)
				continue
			}
			if target, ok := redirectTarget(tok); ok {
				if target == "" {
					pending = true
				} else {
					add(target)
				}
				continue
			}
			if teeDone || k <= i {
				continue
			}
			a := stripQuotes(tok)
			switch r := strings.TrimLeft(a, "0123456789"); {
			case input:
				input = false
			case strings.HasPrefix(r, "<(") || strings.HasPrefix(r, ">("):
				teeDone = true
			case strings.HasPrefix(r, "<"):
				input = r == "<" || r == "<<<"
			case operands || !strings.HasPrefix(a, "-"):
				add(tok)
			case a == "--":
				operands = true
			}
		}
		switch tool {
		case "cd", "pushd":
			to := cdTarget(tokens[i+1:])
			switch {
			case to == "" || !resolvable(to):
				lost = true
			case anchored(to):
				dir, lost = to, false
			case !lost:
				if dir != "" {
					to = dir + "/" + to
				}
				// A path longer than any a system opens is not followed: joining a long chain of
				// relative cds would copy the directory once per cd.
				dir, lost = to, len(to) > maxShellPath
			}
		case "popd":
			lost = true
		}
		if depth < maxUnwrapDepth && i < len(tokens) {
			if inner, ok := innerCommand(tool, tokens[i+1:]); ok {
				writeTargets(inner, depth+1, out, seen)
			}
		}
		if len(*out) >= maxWriteTargets {
			return
		}
	}
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
			if _, ok := redirectTarget(a); !ok {
				return a
			}
		}
	}
	return "~"
}

// redirectTarget reads a word holding an output redirect outside quotes: ">f", ">>f", "2>f", "&>f",
// ">|f", "x>f" (a redirect run into the word before it), or the operator alone, when the target is the
// next word and target is "". ">&2" duplicates a descriptor and ">(cmd)" is a process substitution:
// neither names a file.
func redirectTarget(tok string) (target string, ok bool) {
	var quote byte
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '<':
			// "<>f" opens for reading and writing, and "<(cmd)" is a process substitution: leave both.
			return "", false
		case c == '>':
			if i > 0 && (tok[i-1] == '-' || tok[i-1] == '=') {
				// "->" and "=>" are arrows in code, not redirects.
				return "", false
			}
			rest := strings.TrimPrefix(strings.TrimLeft(tok[i:], ">"), "|")
			if strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "(") {
				return "", false
			}
			return rest, true
		}
	}
	return "", false
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
// working directory is not known.
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
