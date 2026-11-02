package classify

import (
	"encoding/base64"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"
)

const (
	ClassNetwork    = "network"
	ClassPublish    = "publish"
	ClassVCSWrite   = "vcs_write"
	ClassFilesystem = "filesystem"
	ClassReadOnly   = "read_only"
	ClassOther      = "other"
)

var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true, "telnet": true,
	"ftp": true, "socat": true, "http": true, "httpie": true, "aria2c": true,
	"dig": true, "nslookup": true, "host": true, "ping": true, "traceroute": true,
	"aws": true, "gcloud": true, "az": true, "kubectl": true, "gh": true, "glab": true,
	"doctl": true, "heroku": true, "flyctl": true, "vercel": true, "netlify": true,
	// Package runners that fetch what they run, as "npm exec" and "uv run" already count.
	"npx": true, "pnpx": true, "bunx": true, "uvx": true,
	// Cloud storage and sync clients: each moves files to or from somewhere else, which is what an
	// exfiltration needs.
	"rclone": true, "s3cmd": true, "s5cmd": true, "gsutil": true, "bq": true, "azcopy": true,
	"sshfs": true, "smbclient": true, "lftp": true, "tftp": true,
	// Tunnels: each exposes this machine, or reaches another, through a third party.
	"ngrok": true, "cloudflared": true, "tailscale": true,
	// Other clients that make a request or a connection.
	"xh": true, "https": true, "curlie": true, "wget2": true, "axel": true, "websocat": true,
	"wscat": true, "grpcurl": true, "mosh": true, "nmap": true, "whois": true, "ssh-copy-id": true,

	"plink": true, "pscp": true, "psftp": true, "bitsadmin": true,

	"invoke-webrequest": true, "iwr": true, "invoke-restmethod": true, "irm": true,
	"start-bitstransfer": true, "test-netconnection": true, "tnc": true,
	"resolve-dnsname": true, "enter-pssession": true, "new-pssession": true,
	"invoke-command": true, "icm": true, "send-mailmessage": true,
	"install-module": true, "install-script": true, "install-package": true,
	"install-psresource": true, "update-module": true, "save-module": true,
	"save-script": true, "find-module": true,
}

var publishTools = map[string]bool{
	"publish-module": true, "publish-script": true, "publish-psresource": true,
}

var urlOpeners = map[string]bool{
	"start": true, "start-process": true, "saps": true, "explorer": true,
	"invoke-item": true, "ii": true, "open": true, "xdg-open": true,
}

var publishSubcommands = map[string][]string{
	"npm":    {"publish"},
	"nuget":  {"push"},
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

	"winget": {"install", "upgrade", "download", "import", "source"},
	"choco":  {"install", "upgrade", "download", "outdated"},
	"scoop":  {"install", "update", "bucket", "download"},
	"nuget":  {"install", "restore", "update"},
	"dotnet": {"restore", "add", "tool"},

	"net": {"use", "view"},

	"openssl": {"s_client"},
}

var vcsWriteSubcommands = []string{"push"}

var filesystemTools = map[string]bool{
	"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
	"touch": true, "ln": true, "chmod": true, "chown": true, "truncate": true,
	"dd": true, "tee": true, "install": true, "shred": true,

	"del": true, "erase": true, "rd": true, "md": true, "move": true, "copy": true,
	"ren": true, "rename": true, "xcopy": true, "robocopy": true, "mklink": true,
	"attrib": true, "icacls": true, "takeown": true,
	"remove-item": true, "ri": true, "move-item": true, "mi": true,
	"copy-item": true, "cpi": true, "new-item": true, "ni": true,
	"rename-item": true, "rni": true, "set-content": true, "add-content": true, "ac": true,
	"clear-content": true, "out-file": true, "set-itemproperty": true,
	"new-itemproperty": true, "remove-itemproperty": true, "set-acl": true,
	"expand-archive": true, "compress-archive": true,
}

var readOnlyTools = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
	"grep": true, "rg": true, "find": true, "fd": true, "file": true,
	"stat": true, "du": true, "df": true, "pwd": true, "echo": true,
	"which": true, "type": true, "basename": true, "dirname": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "diff": true,
	"jq": true, "yq": true, "date": true, "printenv": true,
	"ps": true, "top": true, "uname": true, "whoami": true, "id": true,

	"dir": true, "findstr": true, "where": true, "hostname": true, "ver": true,
	"tree": true, "more": true, "tasklist": true, "systeminfo": true, "ipconfig": true,
	"get-content": true, "gc": true, "get-childitem": true, "gci": true,
	"get-item": true, "gi": true, "get-itemproperty": true, "get-location": true, "gl": true,
	"get-process": true, "gps": true, "get-service": true, "get-command": true, "gcm": true,
	"get-date": true, "get-help": true, "get-filehash": true, "get-computerinfo": true,
	"select-string": true, "sls": true, "test-path": true, "resolve-path": true,
	"split-path": true, "join-path": true, "write-output": true, "write-host": true,
	"measure-object": true, "select-object": true, "where-object": true,
	"sort-object": true, "format-table": true, "format-list": true, "out-string": true,
	"convertfrom-json": true, "convertto-json": true,
}

const psPos = `(?:^|[(|;&{=,!\n]|\$\()\s*`

var powershellNetwork = regexp.MustCompile(`(?i)(?:` +
	psPos + `(?:invoke-webrequest|invoke-restmethod|start-bitstransfer|test-netconnection|` +
	`resolve-dnsname|enter-pssession|new-pssession|invoke-command|send-mailmessage|` +
	`install-module|install-script|install-package|install-psresource|update-module|` +
	`save-module|save-script|find-module|iwr|irm|icm|tnc)\b|` +

	`\bnet\.(?:webclient|http|sockets|webrequest|dns|servicepointmanager|mail|ftpwebrequest)|` +
	`\.download(?:string|file|data)\b|\.upload(?:string|file|data)\b|` +
	`\bcertutil\b[^\n]*-urlcache` +
	`)`)

var powershellNewObject = regexp.MustCompile(`(?i)\bnew-object\b[^|;\n]*?\bnet\.(?:webclient|sockets|http|webrequest)`)

var powershellPublish = regexp.MustCompile(`(?i)` + psPos + `(?:publish-module|publish-script|publish-psresource)\b`)

var (
	uncShare      = regexp.MustCompile(`(?:^|[\s"'>=(,])\\\\([^\s\\/"'<>|*?]+)[\\/]`)
	uncShareSlash = regexp.MustCompile(`(?i)(?:^|[\s"'>=(,])//([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)/`)
)

func localUNCHost(h string) bool {
	switch strings.ToLower(h) {
	case ".", "localhost", "127.0.0.1", "::1", "wsl$", "wsl.localhost":
		return true
	}
	return false
}

func reachesRemoteShare(text string) bool {
	// uncShare needs two backslashes and uncShareSlash two slashes, both literal.
	if !strings.Contains(text, `\\`) && !strings.Contains(text, "//") {
		return false
	}
	for _, m := range uncShare.FindAllStringSubmatch(text, -1) {
		if !localUNCHost(m[1]) {
			return true
		}
	}
	return uncShareSlash.MatchString(text)
}

const maxUnwrapDepth = 3

func Bash(command string) (argv0, class string) {
	if strings.TrimSpace(command) == "" {
		return "", ClassOther
	}

	segments := splitSegments(command)
	argv0 = argv0Of(segments[0])
	best := classifyCommand(command, 0)

	if best == ClassReadOnly && hasWriteRedirect(command) {
		best = ClassFilesystem
	}
	return argv0, best
}

func classifyCommand(command string, depth int) string {

	best := ""
	for _, seg := range splitSegments(command) {
		if c := classifySegment(seg, depth); severity(c) > severity(best) {
			best = c
		}
	}
	if best == "" {
		best = ClassOther
	}

	// Each pattern runs only where the words it needs appear; see prefilter.go. The words are
	// looked for in command, which holds everything bare does.
	ft := newFoldText(command)
	if depth < maxUnwrapDepth && ft.mayHold(interpreterWords) {
		for _, inner := range inlineCodeCommands(command) {
			if c := classifyCommand(inner, depth+1); severity(c) > severity(best) {
				best = c
			}
		}
	}

	if severity(best) >= severity(ClassPublish) {
		return best
	}
	bare := blankQuoted(command)
	if ft.mayHold(powershellPublishWords) && powershellPublish.MatchString(bare) {
		best = ClassPublish
	}
	if severity(ClassNetwork) > severity(best) &&
		((ft.mayHold(powershellNetworkWords) && powershellNetwork.MatchString(bare)) ||
			(ft.mayHold(powershellNewObjectWords) && powershellNewObject.MatchString(command)) ||
			(ft.mayHold(interpreterWords) && inlineCodeReachesNetwork(command))) {
		best = ClassNetwork
	}
	return best
}

func classifySegment(seg string, depth int) string {
	tokens := tokenize(seg)
	i := skipPrefix(tokens)
	if i >= len(tokens) {
		return ClassOther
	}

	tool := baseName(tokens[i])
	args := tokens[i+1:]
	class := classifyTool(tool, args)

	if depth < maxUnwrapDepth {
		if inner, ok := innerCommand(tool, args); ok {
			if c := classifyCommand(inner, depth+1); severity(c) > severity(class) {
				class = c
			}
		}
	}
	if severity(class) < severity(ClassNetwork) && (reachesRemoteShare(seg) || opensSocket(seg)) {
		class = ClassNetwork
	}
	if class == ClassReadOnly && hasWriteRedirect(seg) {
		class = ClassFilesystem
	}
	return class
}

func classifyTool(tool string, args []string) string {
	sub := firstNonFlag(args)
	if tool == "git" {
		sub = gitSubcommand(args)
		if matchesAny(sub, vcsWriteSubcommands) {
			return ClassVCSWrite
		}
	}
	if publishTools[tool] {
		return ClassPublish
	}
	if tool == "dotnet" && sub == "nuget" && nthNonFlag(args, 1) == "push" {
		return ClassPublish
	}
	if subs, ok := publishSubcommands[tool]; ok && matchesAny(sub, subs) {
		return ClassPublish
	}
	if networkTools[tool] {
		return ClassNetwork
	}
	if urlOpeners[tool] && hasURLArg(args) {
		return ClassNetwork
	}
	if subs, ok := networkSubcommands[tool]; ok && matchesAny(sub, subs) {
		return ClassNetwork
	}
	if filesystemTools[tool] {
		return ClassFilesystem
	}
	if tool == "find" && slices.ContainsFunc(args, func(a string) bool { return findWriteActions[stripQuotes(a)] }) {
		return ClassFilesystem
	}
	if readOnlyTools[tool] {
		return ClassReadOnly
	}
	return ClassOther
}

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

func IsNetworkClass(class string) bool {
	switch class {
	case ClassNetwork, ClassPublish, ClassVCSWrite:
		return true
	}
	return false
}

func splitSegments(command string) []string {
	var segs []string
	start := 0
	cut := func(end int) {
		if strings.TrimSpace(command[start:end]) != "" {
			segs = append(segs, command[start:end])
		}
	}
	n := len(command)
	for i := 0; i < n; i++ {
		switch command[i] {
		case '\n', ';':
			cut(i)
			start = i + 1
		case '|':
			if i > 0 && command[i-1] == '>' {
				// ">|" is a redirect that overrides noclobber, not a pipe.
				continue
			}
			cut(i)
			start = i + 1
			if i+1 < n && command[i+1] == '&' {
				i++
				start = i + 1
			}
		case '&':
			switch {
			case i+1 < n && command[i+1] == '&':
				cut(i)
				i++
				start = i + 1
			case i > 0 && (command[i-1] == '>' || command[i-1] == '<'):

			case i+1 < n && command[i+1] == '>':

			case strings.TrimSpace(command[start:i]) == "":

			default:
				cut(i)
				start = i + 1
			}
		}
	}
	cut(n)
	if len(segs) == 0 {
		return []string{command}
	}
	return segs
}

func tokenize(seg string) []string {
	var toks []string
	sc := tokenScanner{s: seg}
	for tok, ok := sc.next(); ok; tok, ok = sc.next() {
		toks = append(toks, tok)
	}
	return toks
}

// tokenScanner yields tokenize's words one at a time, so a caller that needs only the first few words
// after a point does not split the whole rest of a long command. Splitting it once per match made
// inlineCodeReachesNetwork quadratic: seconds for a 64KB command that names an interpreter often.
type tokenScanner struct {
	s string
	i int
}

func (t *tokenScanner) next() (string, bool) {
	var cur strings.Builder
	for ; t.i < len(t.s); t.i++ {
		c := t.s[t.i]
		switch {
		case c == '"' || c == '\'':
			if j := strings.IndexByte(t.s[t.i+1:], c); j >= 0 {
				cur.WriteString(t.s[t.i : t.i+j+2])
				t.i += j + 1
			} else {
				cur.WriteByte(c)
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f' || c == ')' || c == '`':
			if cur.Len() > 0 {
				t.i++
				return cur.String(), true
			}
		case c == '$' && t.i+1 < len(t.s) && t.s[t.i+1] == '(':
			t.i++
			if cur.Len() > 0 {
				t.i++
				return cur.String(), true
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		return cur.String(), true
	}
	return "", false
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var shellKeywords = map[string]bool{
	"!": true, "if": true, "then": true, "else": true, "elif": true,
	"do": true, "while": true, "until": true,
}

func skipPrefix(tokens []string) int {
	i := 0
	for i < len(tokens) {
		// The tokenizer leaves an opening bracket on the word after it, so "(sudo", "{env", "(!" and
		// "(A=1" are each a prefix behind a bracket. Every check below sees the word without it.
		t := strings.TrimLeft(tokens[i], "({")
		switch {
		case t == "&":
		// A keyword, or opening brackets alone: "(", "{(", "!", "(!".
		case shellKeywords[t] || t == "":
		case envAssignment.MatchString(t):
		default:
			r, ok := runners[baseName(t)]
			if !ok {
				return i
			}
			next, ok := r.skip(tokens, i+1)
			if !ok {
				return i
			}
			i = next
			continue
		}
		i++
	}
	return i
}

// A runner runs the command that follows its own options and operands: sudo, timeout, nice, xargs and
// the like. The command it runs, not the runner, is what the segment does, so skipPrefix steps over the
// runner to it. A runner that runs nothing here (no command follows, or an option such as "command -v"
// or "sudo -l" means it only looks), or that takes its command as one string ("env -S", "flock -c"), is
// itself the command word, and innerCommand reads any string it was given.
type runner struct {
	value      string   // short options that take a value, attached ("-n5") or as the next word
	long       []string // long options that take the next word as their value when no "=" is attached
	none       string   // short options after which the runner runs no command of its own
	noneLong   []string // long options with that meaning
	positional int      // operands before the command: timeout's duration, chroot's root, flock's lock
}

var runners = map[string]runner{
	"sudo":        {value: "CDgprRtTUu", long: []string{"user", "group", "prompt", "close-from", "chdir", "role", "type", "command-timeout", "other-user", "chroot"}, none: "eKlvV", noneLong: []string{"list", "edit", "validate", "version", "help"}},
	"doas":        {value: "u", none: "CLs"},
	"env":         {value: "uC", long: []string{"unset", "chdir"}, none: "S", noneLong: []string{"split-string"}},
	"nice":        {value: "n", long: []string{"adjustment"}},
	"ionice":      {value: "cn", long: []string{"class", "classdata"}, none: "pPu", noneLong: []string{"pid", "pgid", "uid"}},
	"timeout":     {value: "ks", long: []string{"kill-after", "signal"}, positional: 1},
	"stdbuf":      {value: "eio", long: []string{"input", "output", "error"}},
	"nohup":       {},
	"time":        {value: "fo", long: []string{"format", "output"}},
	"exec":        {value: "a"},
	"command":     {none: "vV"},
	"builtin":     {},
	"setsid":      {},
	"chrt":        {value: "DPT", long: []string{"sched-runtime", "sched-period", "sched-deadline"}, none: "mp", noneLong: []string{"max", "pid"}, positional: 1},
	"taskset":     {none: "p", noneLong: []string{"pid"}, positional: 1},
	"unbuffer":    {},
	"caffeinate":  {value: "tw"},
	"xargs":       {value: "adEILnPs", long: []string{"arg-file", "delimiter", "max-args", "max-procs", "max-chars", "max-lines"}},
	"watch":       {value: "nq", long: []string{"interval", "equexit"}},
	"flock":       {value: "Ew", long: []string{"conflict-exit-code", "timeout", "wait"}, none: "c", noneLong: []string{"command"}, positional: 1},
	"chroot":      {positional: 1},
	"strace":      {value: "abeEIoOPsSuUX", none: "p"},
	"ltrace":      {value: "aAeFlnosuwxX", none: "p"},
	"proxychains": {value: "f"},
	"torsocks":    {value: "aPpu"},
	"firejail":    {},
	"cgexec":      {value: "g"},
	"busybox":     {},
}

func init() { runners["proxychains4"] = runners["proxychains"] }

// skip returns where the command that the runner at tokens[i] runs starts, or false when it runs none
// of its own here.
func (r runner) skip(tokens []string, j int) (int, bool) {
	for j < len(tokens) {
		a := stripQuotes(tokens[j])
		if a == "--" {
			j++
			break
		}
		if len(a) < 2 || a[0] != '-' {
			break
		}
		if r.runsNothing(a) {
			return 0, false
		}
		if strings.HasPrefix(a, "--") {
			name, _, attached := strings.Cut(a[2:], "=")
			if !attached && slices.Contains(r.long, name) {
				j++
			}
			j++
			continue
		}
		takes := false
		for k := 1; k < len(a); k++ {
			if strings.IndexByte(r.value, a[k]) >= 0 {
				// "-n" takes the next word; "-n5" has its value attached.
				takes = k == len(a)-1
				break
			}
		}
		if takes {
			j++
		}
		j++
	}
	j += r.positional
	// flock takes -c after its lock file: "flock /tmp/l -c 'cmd'".
	if j >= len(tokens) || r.runsNothing(stripQuotes(tokens[j])) {
		return 0, false
	}
	return j, true
}

// runsNothing says whether option word a means the runner runs no command of its own, before any
// value-taking letter in a cluster.
func (r runner) runsNothing(a string) bool {
	if name, ok := strings.CutPrefix(a, "--"); ok {
		name, _, _ = strings.Cut(name, "=")
		return slices.Contains(r.noneLong, name)
	}
	if len(a) < 2 || a[0] != '-' {
		return false
	}
	for k := 1; k < len(a); k++ {
		if strings.IndexByte(r.none, a[k]) >= 0 {
			return true
		}
		if strings.IndexByte(r.value, a[k]) >= 0 {
			return false
		}
	}
	return false
}

func argv0Of(seg string) string {
	t := tokenize(seg)
	i := skipPrefix(t)
	if i >= len(t) {
		return ""
	}
	return commandWord(t[i], i > 0 && t[i-1] == "&")
}

const maxUnknownArgv0 = 16

var argv0Chars = regexp.MustCompile(`^(?:\[\[?|[a-z0-9_][a-z0-9_.+@-]*)$`)

var commonTools = map[string]bool{
	"invoke-expression": true, "invoke-item": true, "start-process": true,
	"update-alternatives": true, "ansible-playbook": true, "docker-compose": true,
}

func knownTool(name string) bool {
	if networkTools[name] || publishTools[name] || filesystemTools[name] || readOnlyTools[name] || commonTools[name] {
		return true
	}
	_, ok := publishSubcommands[name]
	_, ok2 := networkSubcommands[name]
	return ok || ok2
}

func commandWord(tok string, called bool) string {
	prefix := tok
	if q := strings.IndexAny(tok, `"'`); q >= 0 {
		prefix = tok[:q]
	}
	prefix = strings.TrimLeft(prefix, "({")
	if strings.ContainsAny(prefix, "$()") || strings.Contains(prefix, "::") {
		return ""
	}
	if tok != "" && (tok[0] == '"' || tok[0] == '\'') && !called && !strings.ContainsAny(tok, `/\`) {
		return ""
	}
	name := baseName(tok)
	if !argv0Chars.MatchString(name) {
		return ""
	}
	if !knownTool(name) && len(name) > maxUnknownArgv0 {
		return ""
	}
	return name
}

func stripQuotes(s string) string { return strings.Trim(s, "\"'") }

func joinArgs(args []string) string { return stripQuotes(strings.Join(args, " ")) }

func blankQuoted(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\'' {
			if j := strings.IndexByte(s[i+1:], c); j >= 0 {
				b.WriteByte(' ')
				i += j + 1
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func firstNonFlag(args []string) string { return nthNonFlag(args, 0) }

func nthNonFlag(args []string, n int) string {
	for _, a := range args {
		a = stripQuotes(a)
		if strings.HasPrefix(a, "-") {
			continue
		}
		if n == 0 {
			return a
		}
		n--
	}
	return ""
}

var gitValueFlags = map[string]bool{
	"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true,
	"--super-prefix": true, "--config-env": true, "--attr-source": true,
}

func gitSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := stripQuotes(args[i])
		if !strings.HasPrefix(a, "-") {
			return a
		}
		if gitValueFlags[a] {
			i++
		}
	}
	return ""
}

func hasURLArg(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "://") {
			return true
		}
	}
	return false
}

func matchesAny(s string, candidates []string) bool {
	for _, c := range candidates {
		if s == c {
			return true
		}
	}
	return false
}

var shellCFlag = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

func innerCommand(tool string, args []string) (string, bool) {
	switch tool {
	case "cmd":
		for i, a := range args {
			s := stripQuotes(a)
			if low := strings.ToLower(s); len(low) >= 2 && (low[:2] == "/c" || low[:2] == "/k" || low[:2] == "/r") {

				if inner := joinArgs(append([]string{s[2:]}, args[i+1:]...)); strings.TrimSpace(inner) != "" {
					return inner, true
				}
				return "", false
			}
		}
	case "powershell", "pwsh":
		return powershellInner(args)
	case "bash", "sh", "zsh", "dash", "ksh", "fish", "ash":
		for i, a := range args {
			if shellCFlag.MatchString(stripQuotes(a)) && i+1 < len(args) {
				return joinArgs(args[i+1:]), true
			}
		}
	case "wsl":
		return wslInner(args)
	case "su", "script", "flock":
		// The command is the value of -c (also run together, as in "su -lc" or "script -qc"). The words
		// after it are joined on, as for "bash -c": a quoted command can arrive split at a "&" or ";"
		// inside its quotes, and the rest of it is in those words.
		if v, rest, ok := optionString(args, 'c', "command"); ok {
			return joinArgs(append([]string{v}, rest...)), true
		}
	case "env":
		// env -S splits one string into the command and its first arguments.
		if v, rest, ok := optionString(args, 'S', "split-string"); ok {
			return joinArgs(append([]string{v}, rest...)), true
		}
	case "eval":
		if len(args) > 0 {
			return joinArgs(args), true
		}
	case "find":
		return findExecs(args)
	case "iex", "invoke-expression":
		if len(args) > 0 {
			return joinArgs(args), true
		}
	case "start", "start-process", "saps":

		for i, a := range args {
			s := stripQuotes(a)
			if strings.HasPrefix(s, "-") || (tool == "start" && strings.HasPrefix(s, "/")) {
				continue
			}
			return joinArgs(args[i:]), true
		}
	default:
		if isPython(tool) {
			return pythonModule(args)
		}
		if inner, ok := windowsInner(tool, args); ok {
			return inner, true
		}
	}
	return "", false
}

// optionString finds a short option, alone or last in a cluster ("-c", "-lc"), or a long option, and
// returns its value, attached or the next word, and the words after it. It stops at "--".
func optionString(args []string, short byte, long string) (value string, rest []string, ok bool) {
	next := func(i int) (string, []string, bool) {
		if i+1 >= len(args) {
			return "", nil, false
		}
		return stripQuotes(args[i+1]), args[i+2:], true
	}
	for i, a := range args {
		s := stripQuotes(a)
		switch {
		case s == "--":
			return "", nil, false
		case s == "--"+long:
			return next(i)
		case strings.HasPrefix(s, "--"+long+"="):
			return s[len(long)+3:], args[i+1:], true
		case len(s) >= 2 && s[0] == '-' && s[1] != '-':
			if k := strings.IndexByte(s[1:], short); k >= 0 {
				if v := s[k+2:]; v != "" {
					return v, args[i+1:], true
				}
				return next(i)
			}
		}
	}
	return "", nil, false
}

// find's actions that write files of their own, rather than only list them.
var findWriteActions = map[string]bool{"-delete": true, "-fprint": true, "-fprint0": true, "-fprintf": true, "-fls": true}

// findExecs is every command find runs with -exec, -execdir, -ok or -okdir, joined as one command
// line. Each ends at ";" or at "+" after "{}". splitSegments has already cut at the ";", so an escaped
// one arrives as a bare "\".
func findExecs(args []string) (string, bool) {
	var cmds []string
	for i := 0; i < len(args); i++ {
		switch stripQuotes(args[i]) {
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(args) {
				s := stripQuotes(args[j])
				if s == ";" || s == `\;` || s == `\` || (s == "+" && stripQuotes(args[j-1]) == "{}") {
					break
				}
				j++
			}
			if j > i+1 {
				cmds = append(cmds, joinArgs(args[i+1:j]))
			}
			i = j
		}
	}
	return strings.Join(cmds, "; "), len(cmds) > 0
}

func psIs(name, full string, min int) bool {
	return len(name) >= min && strings.HasPrefix(full, name)
}

func powershellValueFlag(name string) bool {
	return name == "ep" || psIs(name, "executionpolicy", 3) || psIs(name, "windowstyle", 1) ||
		psIs(name, "version", 1) || name == "in" || psIs(name, "inputformat", 2) ||
		psIs(name, "outputformat", 1) || name == "wd" || psIs(name, "workingdirectory", 2) ||
		psIs(name, "configurationname", 4) || psIs(name, "custompipename", 3) ||
		psIs(name, "settingsfile", 3)
}

func powershellInner(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := stripQuotes(args[i])
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "/") {
			return joinArgs(args[i:]), true
		}
		name := strings.ToLower(strings.TrimLeft(a, "-/"))
		switch {
		case name == "":
		case psIs(name, "command", 1):
			return joinArgs(args[i+1:]), i+1 < len(args)
		case name == "e" || name == "ec" || psIs(name, "encodedcommand", 2):
			if i+1 < len(args) {
				return decodeEncodedCommand(args[i+1])
			}
			return "", false
		case psIs(name, "file", 1):
			return "", false
		case powershellValueFlag(name):
			i++
		}
	}
	return "", false
}

func decodeEncodedCommand(s string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(stripQuotes(s))
	if err != nil || len(raw) < 2 || len(raw)%2 != 0 || len(raw) > 1<<16 {
		return "", false
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u)), true
}

func wslInner(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(stripQuotes(args[i]))
		switch {
		case a == "--":
			return joinArgs(args[i+1:]), i+1 < len(args)
		case a == "-d" || a == "--distribution" || a == "-u" || a == "--user" || a == "--cd" || a == "--shell-type":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return joinArgs(args[i:]), true
		}
	}
	return "", false
}

func baseName(tok string) string {

	// A leading "!" is pipeline negation run into the word, as in "(!cp" or "!(cp"; it never names
	// the command, and keeping it would let the negation hide the command from its class.
	if t := strings.TrimRight(strings.TrimLeft(tok, "\"'(){}[]!"), "\"'(){}[]"); t != "" {
		tok = t
	}
	tok = strings.ReplaceAll(tok, `\`, "/")
	if i := strings.LastIndex(tok, "/"); i >= 0 {
		tok = tok[i+1:]
	}
	tok = strings.ToLower(tok)
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		if strings.HasSuffix(tok, ext) && len(tok) > len(ext) {
			return tok[:len(tok)-len(ext)]
		}
	}
	return tok
}

func hasWriteRedirect(command string) bool {
	for i := 0; i < len(command); i++ {
		if command[i] != '>' {
			continue
		}
		rest := command[i+1:]
		rest = strings.TrimLeft(rest, ">")
		// ">|" overrides noclobber and is still a write to the word after it.
		rest = strings.TrimPrefix(rest, "|")
		// The same blanks tokenize splits words at.
		rest = strings.TrimLeft(rest, " \t\r\v\f")
		if strings.HasPrefix(rest, "&") {
			continue
		}
		// A write needs a target. ">;" or "> )" is a syntax error, not a write, and counting it would
		// make "cat >;" filesystem on its own but read_only once it is wrapped and split at the ";".
		if rest != "" && !strings.ContainsRune(";|)\n", rune(rest[0])) {
			return true
		}
	}
	return false
}

// An interpreter given code on its command line, as in python -c or node -e, is classed by what the
// code uses: a network API of its language makes the command network. A URL alone does not, since
// code that only prints one connects nowhere. Code is read from the whole command, not a segment,
// because splitSegments cuts at a ";" inside the quoted code.
type inlineLanguage struct {
	code    func(flag string) bool // whether option flag takes the code as its value
	modules func(flag string) string
	api     *regexp.Regexp

	name  string         // the key in inlineLanguages
	spawn *regexp.Regexp // the language's calls that run a command; see subprocess.go
}

var inlineLanguages = map[string]inlineLanguage{
	"python": {
		code: func(f string) bool { return f == "-c" || shortClusterEndsWith(f, 'c') },
		api:  regexp.MustCompile(`\b(?:urllib|urllib2|urllib3|requests|httpx|aiohttp|http\.client|httplib|socket|ftplib|smtplib|telnetlib|paramiko|websocket|websockets|urlopen|pycurl)\b`),
	},
	"node": {
		code: func(f string) bool { return f == "-e" || f == "-p" || f == "--eval" || f == "--print" || f == "eval" },
		api: regexp.MustCompile(`\bfetch\s*\(|\b(?:require|import)\s*\(\s*['"](?:node:)?(?:https?|http2|net|tls|dgram|dns)['"]|\bfrom\s+['"](?:node:)?(?:https?|http2|net|tls|dgram|dns)['"]|` +
			`\b(?:https?|http2|net|tls|dgram)\.(?:get|request|connect|createConnection|createSocket)\s*\(|\bWebSocket\b|\bXMLHttpRequest\b|\baxios\b|\bDeno\.connect`),
	},
	"perl": {
		code: func(f string) bool {
			return f == "-e" || f == "-E" || shortClusterEndsWith(f, 'e') || shortClusterEndsWith(f, 'E')
		},
		modules: func(f string) string { return strings.TrimPrefix(strings.TrimPrefix(f, "-M"), "-m") },
		api:     regexp.MustCompile(`\b(?:LWP|HTTP::Tiny|HTTP::Request|IO::Socket|Net::(?:HTTP|FTP|SMTP|Ping)|Socket|Mojo::UserAgent|WWW::Mechanize)\b`),
	},
	"ruby": {
		code:    func(f string) bool { return f == "-e" || shortClusterEndsWith(f, 'e') },
		modules: func(f string) string { return strings.TrimPrefix(f, "-r") },
		api:     regexp.MustCompile(`\bNet::(?:HTTP|FTP|SMTP)\b|\bopen-uri\b|\bURI\.open\b|\b(?:TCPSocket|UDPSocket|Socket)\b|\bnet/(?:http|ftp|smtp)\b|\bsocket\b|\b(?:Faraday|HTTParty|RestClient|Excon)\b`),
	},
	"php": {
		code: func(f string) bool { return f == "-r" },
		api:  regexp.MustCompile(`(?i)\bcurl_init\b|\bfsockopen\b|\bstream_socket_client\b|\bget_headers\b|\b(?:file_get_contents|fopen|file|readfile|copy)\s*\(\s*['"](?:https?|ftp)://`),
	},
}

// The interpreter's name may follow a separator, a bracket or a quote ("bash -c 'python -c ...'"),
// and carry a path or .exe.
var interpreterWord = regexp.MustCompile(`(?i)(?:^|[\s;&|(!{'"` + "`" + `])(?:[^\s;&|'"]*[/\\])?(python[0-9.]*|py|node|nodejs|deno|bun|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*)(?:\.exe)?(?:\s|$)`)

func inlineLanguageOf(name string) (inlineLanguage, bool) {
	name = strings.ToLower(name)
	switch {
	case isPython(name):
		return inlineLanguages["python"], true
	case name == "node" || name == "nodejs" || name == "deno" || name == "bun":
		return inlineLanguages["node"], true
	case strings.HasPrefix(name, "perl"):
		return inlineLanguages["perl"], true
	case strings.HasPrefix(name, "ruby"):
		return inlineLanguages["ruby"], true
	case strings.HasPrefix(name, "php"):
		return inlineLanguages["php"], true
	}
	return inlineLanguage{}, false
}

func inlineCodeReachesNetwork(command string) bool {
	return eachInlineCode(command, func(lang inlineLanguage, code string, _ bool) bool {
		return lang.api.MatchString(code)
	})
}

// eachInlineCode calls visit with each piece of code given to an interpreter on the command line, and
// with each module it is told to load (module true), until visit returns true.
func eachInlineCode(command string, visit func(lang inlineLanguage, code string, module bool) bool) bool {
	for _, m := range interpreterWord.FindAllStringSubmatchIndex(command, -1) {
		lang, ok := inlineLanguageOf(command[m[2]:m[3]])
		if !ok {
			continue
		}
		// Only the words up to the code are read, one at a time: the scan stops at the code or at the
		// first word that is not an option, so each match costs what it reads, not the rest of the
		// command.
		sc := tokenScanner{s: command, i: m[1]}
		for tok, ok := sc.next(); ok; tok, ok = sc.next() {
			f := stripQuotes(tok)
			if lang.modules != nil && len(f) > 2 && f[0] == '-' && f[1] != '-' {
				if mod := lang.modules(f); mod != f && visit(lang, mod, true) {
					return true
				}
			}
			if lang.code(f) {
				if code, ok := sc.next(); ok && visit(lang, unquoteCode(code), false) {
					return true
				}
				break
			}
			// deno eval and node's flags come before the code; the first other word is a script.
			if !strings.HasPrefix(f, "-") && f != "eval" {
				break
			}
		}
	}
	return false
}

// shortClusterEndsWith says whether f is a cluster of short options, such as perl's "-ne" or
// python's "-Im", whose last letter is c, so the next word is that option's value.
func shortClusterEndsWith(f string, c byte) bool {
	return len(f) > 2 && f[0] == '-' && f[1] != '-' && f[len(f)-1] == c
}

func isPython(name string) bool {
	return name == "py" || (strings.HasPrefix(name, "python") && strings.Trim(name[len("python"):], "0123456789.") == "")
}

// pythonModule is the command "python -m module args" runs, read as "module args", so that
// python -m pip install and python -m twine upload class as pip and twine do.
func pythonModule(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := stripQuotes(args[i])
		switch {
		case a == "-m" || shortClusterEndsWith(a, 'm'):
			// "-m pip", or run together after other flags: "-Im pip".
			if i+1 < len(args) {
				return joinArgs(args[i+1:]), true
			}
			return "", false
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			return joinArgs(append([]string{a[2:]}, args[i+1:]...)), true
		case a == "-W" || a == "-X":
			i++
		case a == "-c" || shortClusterEndsWith(a, 'c') || !strings.HasPrefix(a, "-"):
			// -c's code, or a script: no module.
			return "", false
		}
	}
	return "", false
}
