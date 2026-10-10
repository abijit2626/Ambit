package classify

import (
	"encoding/base64"
	"regexp"
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
	"jq": true, "yq": true, "date": true, "env": true, "printenv": true,
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

	bare := blankQuoted(command)
	if severity(ClassPublish) > severity(best) && powershellPublish.MatchString(bare) {
		best = ClassPublish
	}
	if severity(ClassNetwork) > severity(best) &&
		(powershellNetwork.MatchString(bare) || powershellNewObject.MatchString(command)) {
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
	if severity(class) < severity(ClassNetwork) && reachesRemoteShare(seg) {
		class = ClassNetwork
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
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c == '"' || c == '\'':
			if j := strings.IndexByte(seg[i+1:], c); j >= 0 {
				cur.WriteString(seg[i : i+j+2])
				i += j + 1
			} else {
				cur.WriteByte(c)
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f':
			flush()
		case c == ')' || c == '`':
			flush()
		case c == '$' && i+1 < len(seg) && seg[i+1] == '(':
			flush()
			i++
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func skipPrefix(tokens []string) int {
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		switch {
		case t == "&" || t == "sudo" || t == "env" || t == "nohup" || t == "exec" || t == "time":
		case envAssignment.MatchString(t):
		default:
			return i
		}
		i++
	}
	return i
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
	}
	return "", false
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

	if t := strings.Trim(tok, "\"'(){}[]"); t != "" {
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
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "&") {
			continue
		}
		if rest != "" {
			return true
		}
	}
	return false
}
