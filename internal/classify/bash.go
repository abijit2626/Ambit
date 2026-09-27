package classify

import (
	"strings"
)

// Command classes. These feed Rule-of-Two bit C and the crosses-to-Wazuh
// filter, and they appear as bash_command_class in flattened events.
const (
	ClassNetwork    = "network"    // can reach the network
	ClassPublish    = "publish"    // publishes a package or artifact
	ClassVCSWrite   = "vcs_write"  // pushes to a remote
	ClassFilesystem = "filesystem" // mutates the filesystem
	ClassReadOnly   = "read_only"  // inspection only
	ClassOther      = "other"      // unrecognized
)

// networkTools reach the network. git and package managers are handled
// separately because whether they are network-touching depends on the
// subcommand.
var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true, "telnet": true,
	"ftp": true, "socat": true, "http": true, "httpie": true, "aria2c": true,
	"dig": true, "nslookup": true, "host": true, "ping": true, "traceroute": true,
	"aws": true, "gcloud": true, "az": true, "kubectl": true, "gh": true, "glab": true,
	"doctl": true, "heroku": true, "flyctl": true, "vercel": true, "netlify": true,
}

// publishSubcommands map a tool to the subcommands that publish artifacts.
var publishSubcommands = map[string][]string{
	"npm":    {"publish"},
	"pnpm":   {"publish"},
	"yarn":   {"publish"},
	"cargo":  {"publish"},
	"gem":    {"push"},
	"twine":  {"upload"},
	"poetry": {"publish"},
	"mvn":    {"deploy"},
	"gradle": {"publish"},
	"docker": {"push"},
	"helm":   {"push"},
}

// networkSubcommands map a tool to the subcommands that touch the network.
// Everything a package manager does that fetches counts.
var networkSubcommands = map[string][]string{
	"npm":      {"install", "i", "ci", "add", "update", "audit", "exec", "dlx"},
	"pnpm":     {"install", "i", "add", "update", "dlx"},
	"yarn":     {"install", "add", "up", "dlx"},
	"pip":      {"install", "download", "wheel"},
	"pip3":     {"install", "download", "wheel"},
	"uv":       {"pip", "add", "sync", "run"},
	"cargo":    {"fetch", "install", "update", "add"},
	"go":       {"get", "mod", "install", "download"},
	"bundle":   {"install", "update"},
	"composer": {"install", "update", "require"},
	"brew":     {"install", "update", "upgrade", "tap"},
	"apt":      {"install", "update", "upgrade"},
	"apt-get":  {"install", "update", "upgrade"},
	"docker":   {"pull", "build", "run"},
	"git":      {"clone", "fetch", "pull", "remote", "ls-remote", "submodule"},
}

// vcsWriteSubcommands are the git subcommands that write to a remote.
var vcsWriteSubcommands = []string{"push"}

// filesystemTools mutate the filesystem without touching the network.
var filesystemTools = map[string]bool{
	"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
	"touch": true, "ln": true, "chmod": true, "chown": true, "truncate": true,
	"dd": true, "tee": true, "install": true, "shred": true,
}

// readOnlyTools only inspect. Kept deliberately small: the cost of wrongly
// calling something read-only is a missed signal, so anything ambiguous falls
// through to ClassOther instead.
var readOnlyTools = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
	"grep": true, "rg": true, "find": true, "fd": true, "file": true,
	"stat": true, "du": true, "df": true, "pwd": true, "echo": true,
	"which": true, "type": true, "basename": true, "dirname": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "diff": true,
	"jq": true, "yq": true, "date": true, "env": true, "printenv": true,
	"ps": true, "top": true, "uname": true, "whoami": true, "id": true,
}

// shellOperators split a command line into separately-executed segments.
var shellOperators = []string{"&&", "||", ";", "|", "\n"}

// Bash classifies a raw shell command string.
//
// This is a heuristic over tokens, not shell parsing, and it is deliberately not
// a security boundary — the OS-enforced sandbox is. Its job is to label events
// for detection, so it errs toward the more severe class: a command containing
// a network tool anywhere is ClassNetwork even if that occurrence is inside a
// quoted string or a comment, because a false network label costs a crossed
// event while a missed one costs the signal.
//
// Known blind spots, all of which the sandbox's network isolation still catches:
// indirection through a variable or an alias, a script invoked by path that
// itself makes requests, base64-decoded commands, and `eval`.
func Bash(command string) (argv0, class string) {
	if strings.TrimSpace(command) == "" {
		return "", ClassOther
	}

	segments := splitSegments(command)
	argv0 = firstToken(segments[0])

	// Rank across all segments and keep the most severe. A compound command is
	// as network-touching as its most network-touching part.
	//
	// best starts empty rather than at ClassOther: ClassOther outranks
	// ClassReadOnly (an unrecognized tool is more suspicious than a known
	// inspection one), so seeding with it would make read_only unreachable.
	best := ""
	for _, seg := range segments {
		if c := classifySegment(seg); severity(c) > severity(best) {
			best = c
		}
	}
	if best == "" {
		best = ClassOther
	}

	// Output redirection to a file mutates the filesystem even when the tool
	// itself is read-only.
	if best == ClassReadOnly && hasWriteRedirect(command) {
		best = ClassFilesystem
	}
	return argv0, best
}

func classifySegment(seg string) string {
	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return ClassOther
	}

	// Skip leading environment assignments (FOO=bar cmd ...) and `sudo`.
	i := 0
	for i < len(tokens) && (strings.Contains(tokens[i], "=") && !strings.HasPrefix(tokens[i], "-") || tokens[i] == "sudo" || tokens[i] == "env") {
		i++
	}
	if i >= len(tokens) {
		return ClassOther
	}

	tool := baseName(tokens[i])
	args := tokens[i+1:]
	sub := firstNonFlag(args)

	if tool == "git" {
		if matchesAny(sub, vcsWriteSubcommands) {
			return ClassVCSWrite
		}
	}
	if subs, ok := publishSubcommands[tool]; ok && matchesAny(sub, subs) {
		return ClassPublish
	}
	if networkTools[tool] {
		return ClassNetwork
	}
	if subs, ok := networkSubcommands[tool]; ok && matchesAny(sub, subs) {
		return ClassNetwork
	}
	if filesystemTools[tool] {
		return ClassFilesystem
	}
	if readOnlyTools[tool] {
		return ClassReadOnly
	}
	return ClassOther
}

// severity orders classes so a compound command takes its most severe part.
// Publish and vcs_write rank above plain network because they are specifically
// the "push something outward" actions the Rule-of-Two gate cares about.
func severity(class string) int {
	switch class {
	case ClassPublish:
		return 50
	case ClassVCSWrite:
		return 45
	case ClassNetwork:
		return 40
	case ClassFilesystem:
		return 30
	case ClassOther:
		return 20
	case ClassReadOnly:
		return 10
	}
	return 0
}

// IsNetworkClass reports whether a class can reach the network, which is what
// Rule-of-Two bit C keys on.
func IsNetworkClass(class string) bool {
	switch class {
	case ClassNetwork, ClassPublish, ClassVCSWrite:
		return true
	}
	return false
}

func splitSegments(command string) []string {
	segs := []string{command}
	for _, op := range shellOperators {
		var next []string
		for _, s := range segs {
			next = append(next, strings.Split(s, op)...)
		}
		segs = next
	}
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{command}
	}
	return out
}

func tokenize(seg string) []string {
	return strings.Fields(strings.NewReplacer("$(", " ", ")", " ", "`", " ").Replace(seg))
}

func firstToken(seg string) string {
	t := tokenize(seg)
	i := 0
	for i < len(t) && (strings.Contains(t[i], "=") && !strings.HasPrefix(t[i], "-") || t[i] == "sudo") {
		i++
	}
	if i >= len(t) {
		return ""
	}
	return baseName(t[i])
}

func firstNonFlag(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func matchesAny(s string, candidates []string) bool {
	for _, c := range candidates {
		if s == c {
			return true
		}
	}
	return false
}

func baseName(tok string) string {
	tok = strings.ReplaceAll(tok, `\`, "/")
	if i := strings.LastIndex(tok, "/"); i >= 0 {
		tok = tok[i+1:]
	}
	return strings.ToLower(tok)
}

// hasWriteRedirect looks for > or >> outside an fd-duplication like 2>&1.
func hasWriteRedirect(command string) bool {
	for i := 0; i < len(command); i++ {
		if command[i] != '>' {
			continue
		}
		rest := command[i+1:]
		rest = strings.TrimLeft(rest, ">")
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "&") {
			continue // fd duplication, not a file write
		}
		if rest != "" {
			return true
		}
	}
	return false
}
