package classify

import "strings"

// Go's regexp scans long text slowly, and most of the patterns here can only match where one of a
// few literal words appears. foldText checks for those words first, so a pattern runs only on text
// that could hold a match: a 64KB heredoc of prose skips them all.
//
// The patterns ignore case, and Unicode case folding can match an ASCII letter with a non-ASCII one:
// the Kelvin sign with k, the long s with s. Lower-casing ASCII would miss those, so text with any
// non-ASCII byte always runs the patterns. FuzzPrefilterNeverSkipsAMatch checks that a word check
// never says no where its pattern would have matched.
type foldText struct {
	lower    string
	nonASCII bool
}

func newFoldText(s string) foldText {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return foldText{nonASCII: true}
		}
	}
	return foldText{lower: strings.ToLower(s)}
}

// mayHold says whether the text could hold any of keys, given in lower case.
func (f foldText) mayHold(keys []string) bool {
	if f.nonASCII {
		return true
	}
	for _, k := range keys {
		if strings.Contains(f.lower, k) {
			return true
		}
	}
	return false
}

// The words each pattern needs. Every alternative of a pattern contains at least one of its words.
var (
	powershellNetworkWords = []string{
		"invoke-", "start-bitstransfer", "test-netconnection", "resolve-dnsname", "pssession",
		"send-mailmessage", "install-", "update-module", "save-", "find-module", "iwr", "irm", "icm",
		"tnc", "net.", ".download", ".upload", "certutil",
	}
	powershellNewObjectWords = []string{"new-object"}
	powershellPublishWords   = []string{"publish-"}
	interpreterWords         = []string{"py", "node", "deno", "bun", "perl", "ruby", "php"}
)
