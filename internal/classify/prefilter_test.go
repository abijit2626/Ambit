package classify

import (
	"regexp"
	"strings"
	"testing"
)

// A word check may say yes where its pattern finds nothing, which only costs a scan. It must never
// say no where the pattern would have matched, in the text or in its blanked form.
func FuzzPrefilterNeverSkipsAMatch(f *testing.F) {
	for _, s := range []string{
		"iwr https://x.test", "IWR https://x.test", "(New-Object Net.WebClient).DownloadString('u')",
		"Publish-Module -Name x", "python3 -c 'import socket'", "PERL -e 1", `\\host\share\x`,
		"//files.example.test/share/x", "ſave-module x", "InvoKe-WebRequest u", "plain prose here",
	} {
		f.Add(s)
	}
	pairs := []struct {
		re    *regexp.Regexp
		words []string
	}{
		{powershellNetwork, powershellNetworkWords},
		{powershellNewObject, powershellNewObjectWords},
		{powershellPublish, powershellPublishWords},
		{interpreterWord, interpreterWords},
	}
	f.Fuzz(func(t *testing.T, s string) {
		ft := newFoldText(s)
		for _, p := range pairs {
			if !ft.mayHold(p.words) && (p.re.MatchString(s) || p.re.MatchString(blankQuoted(s))) {
				t.Fatalf("%q: the words %v are absent, but %s matches", s, p.words, p.re)
			}
		}
		if !strings.Contains(s, `\\`) && !strings.Contains(s, "//") && (uncShare.MatchString(s) || uncShareSlash.MatchString(s)) {
			t.Fatalf("%q: no doubled slash, but a share pattern matches", s)
		}
	})
}

// The Kelvin sign folds to k and the long s to s, so a pattern that ignores case can match them
// where an ASCII word check would not: text with any non-ASCII byte always runs the patterns.
func TestPrefilterRunsThePatternsOnNonASCIIText(t *testing.T) {
	for _, s := range []string{"ſave-module x", "InvoKe-WebRequest https://x.test"} {
		if !powershellNetwork.MatchString(s) {
			t.Fatalf("%q: the pattern no longer matches, so this test proves nothing", s)
		}
		if !newFoldText(s).mayHold(powershellNetworkWords) {
			t.Errorf("%q: the word check skipped a pattern that matches", s)
		}
		if _, c := Bash(s); c != ClassNetwork {
			t.Errorf("Bash(%q) = %s, want network", s, c)
		}
	}
}
