package doctor

import (
	"errors"
	"fmt"

	"github.com/abijit2626/ambit/internal/egress"
)

// egressFinding says whether ambitd will be able to load D9's destination profile. A damaged one turns the
// destination half of D9 off at start with only a log line to say so, which is easy to miss until someone
// wonders why rule 100306 is quiet.
func egressFinding(path string) Finding {
	sum, err := egress.Inspect(path)
	switch {
	case errors.Is(err, egress.ErrDamaged):
		return Finding{Level: Fail, Check: "egress", Detail: fmt.Sprintf("%v; ambitd runs with D9's destination profile off until the file is moved aside", err)}
	case err != nil:
		return Finding{Level: Warn, Check: "egress", Detail: fmt.Sprintf("%v; run doctor as the account ambitd runs as to check it", err)}
	case !sum.Exists:
		return Finding{Level: OK, Check: "egress", Detail: fmt.Sprintf("no destination profile at %s yet; ambitd creates it on the endpoint's first contact with a destination", path)}
	case sum.Full:
		return Finding{Level: Warn, Check: "egress", Detail: fmt.Sprintf("the destination profile at %s holds %d destinations, its cap, so new destinations are no longer reported", path, sum.Destinations)}
	}
	return Finding{Level: OK, Check: "egress", Detail: fmt.Sprintf("the destination profile at %s holds %d destinations", path, sum.Destinations)}
}
