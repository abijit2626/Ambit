package collector

import (
	"net"
	"strings"

	"github.com/abijit2626/ambit/internal/classify"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/features"
	"github.com/abijit2626/ambit/internal/hook"
)

// emitEgress sends an egress_destination event for each destination this endpoint has not contacted
// before: a domain or address a network command names, or a host the sandbox refused. It is D9's
// destination half, in shadow. The destinations are keyed digests of the registrable domain, the same
// value trusted_content_domains and the web taint labels are keyed by, so one host is one destination
// whichever way it was reached.
//
// A destination is learned only once its event reaches the sink. A refused event leaves the profile as it
// was, so the next contact with that destination reports it again, as fp_sighting does.
func (c *Collector) emitEgress(st *sessionState, p *hook.Payload, e *event.Event) {
	if c.egress == nil || e.Tool == nil {
		return
	}
	if e.Kind == event.KindToolPre && e.Tool.Bash != nil && classify.IsNetworkClass(e.Tool.Bash.CommandClass) {
		if f := e.Tool.InputFeatures; f != nil {
			for _, d := range f.Domains {
				c.newDestination(st, e, event.EgressSourceBash, d)
			}
			for _, d := range f.IPs {
				c.newDestination(st, e, event.EgressSourceBash, d)
			}
		}
	}
	for _, x := range toolDenials(p, e) {
		if !strings.HasPrefix(x.op, "network") {
			continue
		}
		if host := deniedHost(x.target); host != "" {
			c.newDestination(st, e, event.EgressSourceSandbox, c.ext.Digest(features.Registrable(host)))
		}
	}
}

func (c *Collector) newDestination(st *sessionState, e *event.Event, source, digest string) {
	if !c.egress.IsNew(digest) {
		if c.egress.Overflow() > 0 && c.egressFull.CompareAndSwap(false, true) {
			c.log.Warn("egress profile is full; new destinations are no longer reported",
				"destinations", c.egress.Size(), "path", c.cfg.EgressProfile())
		}
		return
	}
	n := derivedFrom(st, e, event.KindEgressDestination)
	n.Egress = &event.Egress{Source: source, DestinationDigest: digest}
	if !c.emitDerived(n) {
		return
	}
	if err := c.egress.Record(digest); err != nil {
		c.log.Warn("egress profile not updated; the destination will be reported again", "err", err)
	}
}

// deniedHost is the host in a sandbox target such as example.com:443 or [::1]:443, or "" for a target
// that is not a host.
func deniedHost(target string) string {
	target = strings.TrimSpace(target)
	if rest, ok := strings.CutPrefix(target, "["); ok {
		if i := strings.Index(rest, "]"); i > 0 {
			return strings.ToLower(rest[:i])
		}
		return ""
	}
	if ip := net.ParseIP(target); ip != nil {
		return strings.ToLower(target)
	}
	if i := strings.LastIndex(target, ":"); i >= 0 && isPort(target[i+1:]) {
		target = target[:i]
	}
	if target == "" || strings.ContainsAny(target, "/\\ ") {
		return ""
	}
	if strings.Contains(target, ":") && net.ParseIP(target) == nil {
		return ""
	}
	return strings.ToLower(target)
}

func isPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
