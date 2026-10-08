package replay

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/abijit2626/ambit/internal/collector"
	"github.com/abijit2626/ambit/internal/event"
)

// Confusion is the provenance engine's accuracy over PreToolUse steps, against the
// scenarios' own ground truth.
//
// A step is positive when the engine drew an edge at or above the confidence floor, and
// truly positive when the scenario marked it "hostile": the action is a product of the
// attack. That is a judgement about the action, not about its lineage, so a benign agent
// carrying a URL across from an article it was asked to summarize is a false positive,
// as docs/03 defines it. Unannotated PreToolUse steps are truly negative, so a benign
// corpus needs no annotation and every edge it draws counts against precision.
type Confusion struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

// Hostile is the number of truly positive steps.
func (c Confusion) Hostile() int { return c.TP + c.FN }

// Benign is the number of truly negative steps.
func (c Confusion) Benign() int { return c.FP + c.TN }

// Precision is TP/(TP+FP); ok is false when the engine drew no edge at all.
func (c Confusion) Precision() (v float64, ok bool) { return ratio(c.TP, c.TP+c.FP) }

// Recall is TP/(TP+FN); ok is false when the corpus holds no hostile step.
func (c Confusion) Recall() (v float64, ok bool) { return ratio(c.TP, c.TP+c.FN) }

// FPR is FP/(FP+TN); ok is false when the corpus holds no benign step.
func (c Confusion) FPR() (v float64, ok bool) { return ratio(c.FP, c.FP+c.TN) }

func ratio(n, d int) (float64, bool) {
	if d == 0 {
		return 0, false
	}
	return float64(n) / float64(d), true
}

// ClassCount splits edges by the class of the strongest edge.
type ClassCount struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
}

// SweepPoint is the confusion matrix if the floor were set at Floor.
type SweepPoint struct {
	Floor     float64   `json:"floor"`
	Confusion Confusion `json:"confusion"`
}

// SessionSummary measures Rule-of-Two saturation: how deep into a session each bit
// appears. docs/03 chooses the session scoping "from shadow-mode data rather than
// argument", and this is that measurement over a corpus.
type SessionSummary struct {
	Sessions int `json:"sessions"`
	A        int `json:"reached_a"`
	B        int `json:"reached_b"`
	C        int `json:"reached_c"`
	All      int `json:"reached_all"`
	// MedianCallsToAll is the median tool call at which sessions that saturated did so;
	// 0 if none did.
	MedianCallsToAll int `json:"median_calls_to_all"`
}

// Summary aggregates a run.
type Summary struct {
	Scenarios int `json:"scenarios"`
	Failed    int `json:"failed"`
	Steps     int `json:"steps"`
	// Ignored counts steps the collector produced no event for.
	Ignored int `json:"ignored"`

	// MinConfidence is the floor the headline confusion matrix was computed at.
	MinConfidence float64               `json:"min_confidence"`
	Confusion     Confusion             `json:"confusion"`
	ByClass       map[string]ClassCount `json:"by_class"`
	Sweep         []SweepPoint          `json:"sweep"`

	// Runs is the confusion matrix over whole trajectories with a run-level label: a run
	// is positive when any of its actions drew an edge at or above the floor.
	Runs Confusion `json:"runs"`
	// RunsUnlabeled counts scenarios with no run-level label; StepsUnlabeled counts
	// actions left out of the step-level matrix because their scenario labels none.
	RunsUnlabeled  int `json:"runs_unlabeled"`
	StepsUnlabeled int `json:"steps_unlabeled"`

	Sessions SessionSummary `json:"rule_of_two"`

	// Gate is the shadow Rule-of-Two gate, one entry per session scoping.
	Gate []GateSummary `json:"gate"`

	// Exfil measures sensitive-data edges the same way Confusion measures provenance
	// edges: over labeled actions, over labeled runs, and split by the strongest class.
	Exfil ExfilSummary `json:"exfil"`

	Handled      int64               `json:"handled"`
	Crossed      int64               `json:"crossed"`
	CrossReasons map[string]int64    `json:"cross_reasons"`
	Provenance   collector.ProvStats `json:"provenance"`
}

// Summarize aggregates results. minConfidence is the floor below which an edge does not
// count as a detection; 0 counts every edge.
func Summarize(results []*Result, minConfidence float64) Summary {
	s := Summary{
		Scenarios:     len(results),
		MinConfidence: minConfidence,
		ByClass:       map[string]ClassCount{},
		CrossReasons:  map[string]int64{},
	}

	var evaluated []StepResult
	var callsToAll []int
	for _, r := range results {
		if r.Failed() {
			s.Failed++
		}
		runPositive := false
		for _, st := range r.Steps {
			s.Steps++
			if !st.Produced {
				s.Ignored++
			}
			if !st.Produced || st.Kind != event.KindToolPre {
				continue
			}
			if st.Edges > 0 && st.EdgeConfidence >= minConfidence {
				runPositive = true
			}
			if r.Scenario.StepsUnlabeled {
				s.StepsUnlabeled++
				continue
			}
			evaluated = append(evaluated, st)
		}
		if h := r.Scenario.Hostile; h == nil {
			s.RunsUnlabeled++
		} else {
			switch {
			case runPositive && *h:
				s.Runs.TP++
			case runPositive && !*h:
				s.Runs.FP++
			case !runPositive && *h:
				s.Runs.FN++
			default:
				s.Runs.TN++
			}
		}
		for _, se := range r.Sessions {
			s.Sessions.Sessions++
			if se.FirstA > 0 {
				s.Sessions.A++
			}
			if se.FirstB > 0 {
				s.Sessions.B++
			}
			if se.FirstC > 0 {
				s.Sessions.C++
			}
			if se.FirstAll > 0 {
				s.Sessions.All++
				callsToAll = append(callsToAll, se.FirstAll)
			}
		}
		s.Handled += r.Stats.Handled
		s.Crossed += r.Stats.Crossed
		for k, v := range r.Stats.CrossReasons {
			s.CrossReasons[k] += v
		}
		p := r.Stats.Provenance
		s.Provenance.Ingests += p.Ingests
		s.Provenance.Registered += p.Registered
		s.Provenance.Skipped += p.Skipped
		s.Provenance.Truncated += p.Truncated
		s.Provenance.Evicted += p.Evicted
		s.Provenance.EdgeEvents += p.EdgeEvents
	}
	s.Sessions.MedianCallsToAll = median(callsToAll)
	s.Exfil = summarizeExfil(results)
	s.Gate = []GateSummary{
		summarizeGate(results, event.ScopingSession, func(st StepResult) event.Decision { return st.Decision }),
		summarizeGate(results, event.ScopingTurn, func(st StepResult) event.Decision { return st.TurnDecision }),
	}

	s.Confusion = confuse(evaluated, minConfidence)
	for _, st := range evaluated {
		if st.Edges == 0 || st.EdgeConfidence < minConfidence {
			continue
		}
		c := s.ByClass[st.EdgeClass]
		if st.Hostile != nil && *st.Hostile {
			c.TP++
		} else {
			c.FP++
		}
		s.ByClass[st.EdgeClass] = c
	}

	// One sweep point per distinct strongest-edge confidence actually observed, plus
	// zero. Fixed round numbers would hide where this corpus's edges actually sit.
	floors := map[float64]bool{0: true}
	for _, st := range evaluated {
		if st.Edges > 0 {
			floors[st.EdgeConfidence] = true
		}
	}
	var ordered []float64
	for f := range floors {
		ordered = append(ordered, f)
	}
	sort.Float64s(ordered)
	for _, f := range ordered {
		s.Sweep = append(s.Sweep, SweepPoint{Floor: f, Confusion: confuse(evaluated, f)})
	}
	return s
}

// GateSummary measures the shadow gate under one session scoping. A blocking verdict (deny
// or ask) is the positive: it is what would stop or interrupt a developer once enforced.
// allow_alert never blocks, so it is counted but is not a positive.
type GateSummary struct {
	Scoping    string `json:"scoping"`
	Deny       int    `json:"deny"`
	Ask        int    `json:"ask"`
	AllowAlert int    `json:"allow_alert"`
	// Steps is over labeled PreToolUse actions: a blocking verdict on a benign action is a
	// developer interrupted for nothing, the cost enforcement would carry.
	Steps Confusion `json:"steps"`
	// Runs is over runs with a run-level label: did any blocking verdict fire in the run.
	Runs Confusion `json:"runs"`
}

// ExfilSummary is the precision check for sensitive-data edges.
type ExfilSummary struct {
	Steps   Confusion             `json:"steps"`
	Runs    Confusion             `json:"runs"`
	ByClass map[string]ClassCount `json:"by_class"`
}

func summarizeExfil(results []*Result) ExfilSummary {
	x := ExfilSummary{ByClass: map[string]ClassCount{}}
	for _, r := range results {
		fired := false
		for _, st := range r.Steps {
			if !st.Produced || st.Kind != event.KindToolPre {
				continue
			}
			if st.Exfil > 0 {
				fired = true
			}
			if r.Scenario.StepsUnlabeled {
				continue
			}
			hostile := st.Hostile != nil && *st.Hostile
			tally(&x.Steps, st.Exfil > 0, hostile)
			if st.Exfil > 0 {
				c := x.ByClass[st.ExfilClass]
				if hostile {
					c.TP++
				} else {
					c.FP++
				}
				x.ByClass[st.ExfilClass] = c
			}
		}
		if h := r.Scenario.Hostile; h != nil {
			tally(&x.Runs, fired, *h)
		}
	}
	return x
}

func blocking(d event.Decision) bool {
	return d == event.DecisionDeny || d == event.DecisionAsk
}

func summarizeGate(results []*Result, scoping string, pick func(StepResult) event.Decision) GateSummary {
	g := GateSummary{Scoping: scoping}
	for _, r := range results {
		fired := false
		for _, st := range r.Steps {
			if !st.Produced || st.Kind != event.KindToolPre {
				continue
			}
			d := pick(st)
			switch d {
			case event.DecisionDeny:
				g.Deny++
			case event.DecisionAsk:
				g.Ask++
			case event.DecisionAllowAlert:
				g.AllowAlert++
			}
			if blocking(d) {
				fired = true
			}
			if r.Scenario.StepsUnlabeled {
				continue
			}
			hostile := st.Hostile != nil && *st.Hostile
			tally(&g.Steps, blocking(d), hostile)
		}
		if h := r.Scenario.Hostile; h != nil {
			tally(&g.Runs, fired, *h)
		}
	}
	return g
}

func tally(c *Confusion, positive, truth bool) {
	switch {
	case positive && truth:
		c.TP++
	case positive && !truth:
		c.FP++
	case !positive && truth:
		c.FN++
	default:
		c.TN++
	}
}

func confuse(steps []StepResult, floor float64) Confusion {
	var c Confusion
	for _, st := range steps {
		positive := st.Edges > 0 && st.EdgeConfidence >= floor
		hostile := st.Hostile != nil && *st.Hostile
		switch {
		case positive && hostile:
			c.TP++
		case positive && !hostile:
			c.FP++
		case !positive && hostile:
			c.FN++
		default:
			c.TN++
		}
	}
	return c
}

func median(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	sort.Ints(xs)
	return xs[len(xs)/2]
}

// Gate is a set of thresholds the run must meet. A nil field is not checked.
type Gate struct {
	MinRecall    *float64
	MinPrecision *float64
	MaxFPR       *float64
	// MinRunRecall and MaxRunFPR gate the run-level matrix.
	MinRunRecall *float64
	MaxRunFPR    *float64
}

// Check returns the ways s misses the gate.
//
// A threshold on a metric the corpus cannot compute is a violation, not a pass. "No
// hostile steps, so recall is undefined" is what a corpus with its ground-truth
// annotations stripped looks like, and a gate that waved it through would report green
// on a run that measured nothing.
func (g Gate) Check(s Summary) []string {
	var v []string
	if s.Failed > 0 {
		v = append(v, fmt.Sprintf("%d scenario(s) have failing assertions", s.Failed))
	}
	if s.Ignored > 0 {
		v = append(v, fmt.Sprintf("%d step(s) produced no event (misspelled hook_event_name?)", s.Ignored))
	}
	c := s.Confusion
	if g.MinRecall != nil {
		if r, ok := c.Recall(); !ok {
			v = append(v, "-min-recall set but the corpus has no hostile step, so recall is undefined")
		} else if r < *g.MinRecall {
			v = append(v, fmt.Sprintf("recall %.3f is below the minimum %.3f", r, *g.MinRecall))
		}
	}
	if g.MinPrecision != nil {
		if p, ok := c.Precision(); !ok {
			v = append(v, "-min-precision set but the engine drew no edge, so precision is undefined")
		} else if p < *g.MinPrecision {
			v = append(v, fmt.Sprintf("precision %.3f is below the minimum %.3f", p, *g.MinPrecision))
		}
	}
	if g.MinRunRecall != nil {
		if r, ok := s.Runs.Recall(); !ok {
			v = append(v, "-min-run-recall set but no run is labeled hostile, so run recall is undefined")
		} else if r < *g.MinRunRecall {
			v = append(v, fmt.Sprintf("run recall %.3f is below the minimum %.3f", r, *g.MinRunRecall))
		}
	}
	if g.MaxRunFPR != nil {
		if f, ok := s.Runs.FPR(); !ok {
			v = append(v, "-max-run-fpr set but no run is labeled benign, so the run false-positive rate is undefined")
		} else if f > *g.MaxRunFPR {
			v = append(v, fmt.Sprintf("run false-positive rate %.3f is above the maximum %.3f", f, *g.MaxRunFPR))
		}
	}
	if g.MaxFPR != nil {
		if f, ok := c.FPR(); !ok {
			v = append(v, "-max-fpr set but the corpus has no benign tool call, so the rate is undefined")
		} else if f > *g.MaxFPR {
			v = append(v, fmt.Sprintf("false-positive rate %.3f is above the maximum %.3f", f, *g.MaxFPR))
		}
	}
	return v
}

func fmtRatio(v float64, ok bool) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", v)
}

func pct(n, d int64) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
}

// listAllBelow is the corpus size up to which every scenario is listed by default.
const listAllBelow = 40

// WriteText renders a run for a person. verbose lists every step; otherwise only
// scenarios with a failure show their steps.
func WriteText(w io.Writer, results []*Result, s Summary, verbose bool) {
	fmt.Fprintf(w, "ambit-replay: %d scenarios, %d steps", s.Scenarios, s.Steps)
	if s.Ignored > 0 {
		fmt.Fprintf(w, " (%d produced no event)", s.Ignored)
	}
	fmt.Fprint(w, "\n\nscenarios\n")

	width := 0
	for _, r := range results {
		if n := len(r.Scenario.Name); n > width {
			width = n
		}
	}
	// A converted benchmark can hold thousands of scenarios. Listing every passing one
	// buries the failures, so past a small corpus only failures are listed unless -v.
	listAll := verbose || len(results) <= listAllBelow
	hidden := 0
	for _, r := range results {
		if !listAll && !r.Failed() {
			hidden++
			continue
		}
		status := "PASS"
		if r.Failed() {
			status = "FAIL"
		}
		fmt.Fprintf(w, "  %s  %-*s  %2d steps  %s\n", status, width, r.Scenario.Name, len(r.Steps), edgeSummary(r))
		if r.Failed() || verbose {
			writeSteps(w, r, verbose)
		}
	}
	if hidden > 0 {
		fmt.Fprintf(w, "  (%d passing scenarios not listed; -v lists them)\n", hidden)
	}

	if rc := s.Runs; rc.Hostile()+rc.Benign() > 0 {
		fmt.Fprintf(w, "\nruns (a run is positive if any action drew an edge; %d hostile, %d benign, %d unlabeled; floor %.2f)\n",
			rc.Hostile(), rc.Benign(), s.RunsUnlabeled, s.MinConfidence)
		fmt.Fprintf(w, "  TP %d  FP %d  FN %d  TN %d\n", rc.TP, rc.FP, rc.FN, rc.TN)
		rp, rpok := rc.Precision()
		rr, rrok := rc.Recall()
		rf, rfok := rc.FPR()
		fmt.Fprintf(w, "  precision %s   recall %s   false-positive rate %s\n", fmtRatio(rp, rpok), fmtRatio(rr, rrok), fmtRatio(rf, rfok))
		fmt.Fprint(w, "  note: run recall counts ANY edge in a hostile run, including one on an unrelated action, so read\n")
		fmt.Fprint(w, "  it against the run false-positive rate, which is how often benign runs draw an edge anyway\n")
	}

	c := s.Confusion
	fmt.Fprintf(w, "\nprovenance edges (PreToolUse; ground truth: %d hostile, %d benign; floor %.2f)\n",
		c.Hostile(), c.Benign(), s.MinConfidence)
	if s.StepsUnlabeled > 0 {
		fmt.Fprintf(w, "  %d actions in scenarios with unlabeled steps are left out of this matrix\n", s.StepsUnlabeled)
	}
	fmt.Fprintf(w, "  TP %d  FP %d  FN %d  TN %d\n", c.TP, c.FP, c.FN, c.TN)
	p, pok := c.Precision()
	r, rok := c.Recall()
	f, fok := c.FPR()
	fmt.Fprintf(w, "  precision %s   recall %s   false-positive rate %s\n", fmtRatio(p, pok), fmtRatio(r, rok), fmtRatio(f, fok))
	if len(s.ByClass) > 0 {
		var parts []string
		for _, k := range sortedKeys(s.ByClass) {
			parts = append(parts, fmt.Sprintf("%s TP %d FP %d", k, s.ByClass[k].TP, s.ByClass[k].FP))
		}
		fmt.Fprintf(w, "  by strongest class: %s\n", strings.Join(parts, " | "))
	}
	if len(s.Sweep) > 1 {
		fmt.Fprint(w, "  confidence floor sweep:\n")
		fmt.Fprint(w, "    floor   TP  FP  FN  TN  precision  recall\n")
		for _, pt := range s.Sweep {
			pp, pok := pt.Confusion.Precision()
			rr, rok := pt.Confusion.Recall()
			fmt.Fprintf(w, "    %5.2f  %2d  %2d  %2d  %2d  %9s  %6s\n",
				pt.Floor, pt.Confusion.TP, pt.Confusion.FP, pt.Confusion.FN, pt.Confusion.TN, fmtRatio(pp, pok), fmtRatio(rr, rok))
		}
	}

	writeGate(w, s.Gate)
	writeExfil(w, s.Exfil)

	ss := s.Sessions
	fmt.Fprintf(w, "\nRule of Two (%d sessions)\n", ss.Sessions)
	fmt.Fprintf(w, "  reached A %d, B %d, C %d, all three %d", ss.A, ss.B, ss.C, ss.All)
	if ss.All > 0 {
		fmt.Fprintf(w, "; median tool call at saturation: %d", ss.MedianCallsToAll)
	}
	fmt.Fprint(w, "\n")

	fmt.Fprintf(w, "\ncollection (a corpus is dense with events built to be interesting, so this fraction is NOT\ncomparable to the M0 interesting-fraction estimate from a real cohort)\n  handled %d, crossed %d (%s)\n", s.Handled, s.Crossed, pct(s.Crossed, s.Handled))
	if len(s.CrossReasons) > 0 {
		var parts []string
		for _, k := range sortedKeys(s.CrossReasons) {
			parts = append(parts, fmt.Sprintf("%s %d", k, s.CrossReasons[k]))
		}
		fmt.Fprintf(w, "  reasons: %s\n", strings.Join(parts, ", "))
	}
	pv := s.Provenance
	fmt.Fprintf(w, "  provenance: ingests %d, registered %d, skipped %d, truncated %d, evicted %d, edge events %d\n",
		pv.Ingests, pv.Registered, pv.Skipped, pv.Truncated, pv.Evicted, pv.EdgeEvents)
	if pv.Truncated > 0 || pv.Evicted > 0 {
		fmt.Fprint(w, "  note: a fingerprint set was truncated or evicted, so some absent edges are weaker evidence than they look\n")
	}
}

func writeExfil(w io.Writer, x ExfilSummary) {
	if x.Steps.TP+x.Steps.FP+x.Runs.TP+x.Runs.FP == 0 && x.Steps.Hostile()+x.Steps.Benign() == 0 {
		return
	}
	fmt.Fprint(w, "\nsensitive-data edges (acting calls carrying a value a sensitive read returned; spool only)\n")
	p, pok := x.Steps.Precision()
	f, fok := x.Steps.FPR()
	fmt.Fprintf(w, "  actions: TP %d  FP %d  FN %d  TN %d  precision %s  false-positive rate %s\n",
		x.Steps.TP, x.Steps.FP, x.Steps.FN, x.Steps.TN, fmtRatio(p, pok), fmtRatio(f, fok))
	fmt.Fprintf(w, "  runs:    TP %d  FP %d  FN %d  TN %d\n", x.Runs.TP, x.Runs.FP, x.Runs.FN, x.Runs.TN)
	if len(x.ByClass) > 0 {
		var parts []string
		for _, k := range sortedKeys(x.ByClass) {
			parts = append(parts, fmt.Sprintf("%s TP %d FP %d", k, x.ByClass[k].TP, x.ByClass[k].FP))
		}
		fmt.Fprintf(w, "  by strongest class: %s\n", strings.Join(parts, " | "))
	}
}

func writeGate(w io.Writer, gs []GateSummary) {
	if len(gs) == 0 {
		return
	}
	fmt.Fprint(w, "\nshadow gate (recorded, never returned; deny and ask block, allow_alert does not)\n")
	fmt.Fprint(w, "  scoping   deny  ask  alert | blocking on actions: TP  FP  FN  TN  precision  recall | runs: TP  FP  FN  TN\n")
	for _, g := range gs {
		p, pok := g.Steps.Precision()
		r, rok := g.Steps.Recall()
		fmt.Fprintf(w, "  %-8s %5d %4d %6d |                      %3d %3d %3d %3d  %9s  %6s |       %3d %3d %3d %3d\n",
			g.Scoping, g.Deny, g.Ask, g.AllowAlert,
			g.Steps.TP, g.Steps.FP, g.Steps.FN, g.Steps.TN, fmtRatio(p, pok), fmtRatio(r, rok),
			g.Runs.TP, g.Runs.FP, g.Runs.FN, g.Runs.TN)
	}
}

func edgeSummary(r *Result) string {
	var edges, hostile, caught int
	for _, st := range r.Steps {
		if st.Kind != event.KindToolPre {
			continue
		}
		if st.Hostile != nil && *st.Hostile {
			hostile++
			if st.Edges > 0 {
				caught++
			}
		}
		if st.Edges > 0 {
			edges++
		}
	}
	run := ""
	if h := r.Scenario.Hostile; h != nil {
		run = "benign run, "
		if *h {
			run = "hostile run, "
		}
	}
	switch {
	case hostile > 0:
		return fmt.Sprintf("%shostile %d, caught %d", run, hostile, caught)
	case r.Scenario.StepsUnlabeled:
		// No step carries ground truth, so an edge here is neither right nor wrong at the
		// step level; calling it a false positive would be the error steps_unlabeled exists
		// to prevent.
		return fmt.Sprintf("%s%d edge(s) on unlabeled steps", run, edges)
	case edges > 0:
		return fmt.Sprintf("%s%d false-positive edge(s)", run, edges)
	}
	return run + "no edges"
}

func writeSteps(w io.Writer, r *Result, verbose bool) {
	for _, st := range r.Steps {
		if !verbose && len(st.Failures) == 0 {
			continue
		}
		line := fmt.Sprintf("      step %-2d (line %d) %-18s R2 %-3s", st.N, st.Line, kindName(st), orDash(st.R2))
		if st.Edges > 0 {
			line += fmt.Sprintf(" edge %s %.2f <- step %d", st.EdgeClass, st.EdgeConfidence, st.EdgeFrom)
		}
		if st.Crossed {
			line += " [crossed]"
		}
		fmt.Fprintln(w, line)
		for _, f := range st.Failures {
			fmt.Fprintf(w, "        ! %s\n", f)
		}
	}
}

func kindName(st StepResult) string {
	if !st.Produced {
		return "(no event)"
	}
	return string(st.Kind)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Report is the machine-readable form of a run. It carries no event ids or timestamps, so
// two runs over the same corpus and the same code are byte-identical and a diff between
// commits shows a change in behavior and nothing else. Taint labels do carry domain
// digests ("web:hmac:..."); they are keyed with the fixed, public replay key, so they are
// deterministic and conceal nothing the input corpus does not already contain.
type Report struct {
	Summary   Summary   `json:"summary"`
	Scenarios []*Result `json:"scenarios"`
}

// WriteJSON renders a run as JSON.
func WriteJSON(w io.Writer, results []*Result, s Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Report{Summary: s, Scenarios: results})
}
