package classify

import (
	"strings"
	"testing"
)

// Classification runs on the collector's ingest queue for every Bash and PowerShell call, so its
// cost per byte decides how far a burst of large commands, such as heredocs that write files, can
// fall behind.
func BenchmarkBash(b *testing.B) {
	for _, c := range []struct{ name, cmd string }{
		{"short", "git push origin main"},
		{"typical", "cd /home/dev/src/myrepo && npm ci && npm test -- --coverage 2>&1 | tail -50"},
		{"heredoc64KB", "cat > notes.md <<'EOF'\n" + strings.Repeat("Some prose about the design, with a path/like/this and a word.\n", 1040) + "EOF"},
		{"words64KB", "echo " + strings.Repeat("abcdefgh ", 7200)},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.cmd)))
			for i := 0; i < b.N; i++ {
				Bash(c.cmd)
			}
		})
	}
}
