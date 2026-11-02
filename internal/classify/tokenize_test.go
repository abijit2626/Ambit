package classify

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// referenceTokenize is tokenize as it was before it read through tokenScanner, kept to check that the
// scanner splits every input the same way.
func referenceTokenize(seg string) []string {
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

func FuzzTokenScannerSplitsAsTokenizeDid(f *testing.F) {
	for _, s := range []string{
		`a b`, `echo "a b" 'c d'`, `x$(y)z`, `$(`, `a)b`, "a`b`c", `'unclosed b`, `"" ''`, "a\t\v\f\rb", `$($(a`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := tokenize(s), referenceTokenize(s); !reflect.DeepEqual(got, want) {
			t.Fatalf("tokenize(%q) = %q, want %q", s, got, want)
		}
	})
}

// The inline-code check read the whole rest of the command for every interpreter name in it, which
// took seconds for a 64KB command naming one thousands of times. Hook bodies can be 4MB, so that was
// a way to stall the collector. The bound is loose: the quadratic version needs about a minute here.
func TestClassifyingALongCommandStaysLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("times a 256KB command")
	}
	for name, cmd := range map[string]string{
		"interpreter names": "cat > notes.md <<'EOF'\n" + strings.Repeat("run node x\n", 24000) + "EOF",
		"inline code flags": strings.Repeat("python -c x ", 21000),
	} {
		start := time.Now()
		Bash(cmd)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: classifying %d bytes took %v", name, len(cmd), d)
		}
	}
}
