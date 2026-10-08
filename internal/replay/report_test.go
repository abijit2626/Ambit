package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abijit2626/ambit/internal/collector"
	"github.com/abijit2626/ambit/internal/event"
)

func tp(b bool) *bool { return &b }

// pre builds a PreToolUse result with the given ground truth and strongest edge.
func pre(hostile *bool, class string, conf float64) StepResult {
	st := StepResult{Produced: true, Kind: event.KindToolPre, Hostile: hostile}
	if class != "" {
		st.Edges, st.EdgeClass, st.EdgeConfidence = 1, class, conf
	}
	return st
}

func resultOf(steps ...StepResult) *Result { return &Result{Steps: steps} }

func TestConfusionCountsEachQuadrant(t *testing.T) {
	r := resultOf(
		pre(tp(true), "url", 0.95),  // TP
		pre(tp(true), "", 0),        // FN
		pre(tp(false), "url", 0.95), // FP
		pre(tp(false), "", 0),       // TN
		pre(nil, "", 0),             // unannotated: not hostile, so TN
		pre(nil, "domain", 0.80),    // unannotated with an edge: FP
	)
	c := Summarize([]*Result{r}, 0).Confusion
	if c != (Confusion{TP: 1, FP: 2, FN: 1, TN: 2}) {
		t.Errorf("confusion = %+v, want TP1 FP2 FN1 TN2", c)
	}
	if c.Hostile() != 2 || c.Benign() != 4 {
		t.Errorf("Hostile/Benign = %d/%d, want 2/4", c.Hostile(), c.Benign())
	}
	p, _ := c.Precision()
	rc, _ := c.Recall()
	f, _ := c.FPR()
	if p != 1.0/3 || rc != 0.5 || f != 0.5 {
		t.Errorf("precision %v recall %v fpr %v, want 1/3, 1/2, 1/2", p, rc, f)
	}
}

func TestConfusionIgnoresEventsThatAreNotActions(t *testing.T) {
	post := StepResult{Produced: true, Kind: event.KindToolPost, Edges: 1, EdgeClass: "url", EdgeConfidence: 0.95}
	unmodelled := StepResult{Produced: false, Kind: event.KindToolPre}
	c := Summarize([]*Result{resultOf(post, unmodelled, pre(tp(false), "", 0))}, 0).Confusion
	if c != (Confusion{TN: 1}) {
		t.Errorf("confusion = %+v; only a produced PreToolUse is an action to be judged", c)
	}
}

func TestMetricsAreUndefinedRatherThanZeroWhenThereIsNothingToDivide(t *testing.T) {
	c := Confusion{TN: 5}
	if _, ok := c.Precision(); ok {
		t.Error("precision with no edges drawn is undefined, not 0")
	}
	if _, ok := c.Recall(); ok {
		t.Error("recall with no hostile step is undefined, not 0 or 1")
	}
	if _, ok := (Confusion{TP: 1}).FPR(); ok {
		t.Error("FPR with no benign step is undefined")
	}
}

func TestConfidenceFloorMovesEdgesOutOfTheCount(t *testing.T) {
	r := resultOf(
		pre(tp(true), "url", 0.95),
		pre(tp(false), "domain", 0.40),
	)
	at0 := Summarize([]*Result{r}, 0)
	if at0.Confusion.FP != 1 {
		t.Fatalf("at floor 0 the low-confidence edge should count: %+v", at0.Confusion)
	}
	at5 := Summarize([]*Result{r}, 0.5)
	if at5.Confusion != (Confusion{TP: 1, TN: 1}) {
		t.Errorf("at floor 0.5 = %+v, want the 0.40 edge to stop counting", at5.Confusion)
	}
	if got := at5.ByClass["domain"]; got.FP != 0 {
		t.Errorf("ByClass counted an edge below the floor: %+v", got)
	}
}

func TestSweepHasOnePointPerObservedConfidence(t *testing.T) {
	s := Summarize([]*Result{resultOf(
		pre(tp(true), "url", 0.95),
		pre(tp(false), "domain", 0.40),
		pre(tp(false), "url", 0.95),
	)}, 0)
	var floors []float64
	for _, p := range s.Sweep {
		floors = append(floors, p.Floor)
	}
	want := []float64{0, 0.40, 0.95}
	if len(floors) != len(want) {
		t.Fatalf("floors = %v, want %v", floors, want)
	}
	for i := range want {
		if floors[i] != want[i] {
			t.Errorf("floors = %v, want %v", floors, want)
		}
	}
	// Raising the floor can only remove detections, never add them.
	for i := 1; i < len(s.Sweep); i++ {
		if s.Sweep[i].Confusion.TP+s.Sweep[i].Confusion.FP > s.Sweep[i-1].Confusion.TP+s.Sweep[i-1].Confusion.FP {
			t.Errorf("a higher floor produced more detections: %+v", s.Sweep)
		}
	}
}

func TestByClassSplitsByTheStrongestEdge(t *testing.T) {
	s := Summarize([]*Result{resultOf(
		pre(tp(true), "url", 0.95),
		pre(tp(true), "email", 0.90),
		pre(tp(false), "url", 0.95),
	)}, 0)
	if s.ByClass["url"] != (ClassCount{TP: 1, FP: 1}) || s.ByClass["email"] != (ClassCount{TP: 1}) {
		t.Errorf("ByClass = %+v", s.ByClass)
	}
}

func TestSummaryCountsFailuresAndIgnoredSteps(t *testing.T) {
	ok := resultOf(pre(nil, "", 0))
	bad := resultOf(StepResult{Produced: false}, StepResult{Produced: true, Failures: []string{"x"}})
	s := Summarize([]*Result{ok, bad}, 0)
	if s.Scenarios != 2 || s.Failed != 1 || s.Ignored != 1 || s.Steps != 3 {
		t.Errorf("summary = %+v", s)
	}
}

func TestRuleOfTwoSaturationSummary(t *testing.T) {
	r := &Result{Sessions: []SessionR2{
		{FirstA: 1, FirstB: 2, FirstC: 3, FirstAll: 3},
		{FirstA: 1, FirstB: 4, FirstC: 5, FirstAll: 5},
		{FirstA: 2},
		{},
	}}
	ss := Summarize([]*Result{r}, 0).Sessions
	if ss.Sessions != 4 || ss.A != 3 || ss.B != 2 || ss.C != 2 || ss.All != 2 {
		t.Errorf("sessions = %+v", ss)
	}
	if ss.MedianCallsToAll != 5 {
		t.Errorf("median = %d, want 5", ss.MedianCallsToAll)
	}
	if got := Summarize([]*Result{{Sessions: []SessionR2{{FirstA: 1}}}}, 0).Sessions.MedianCallsToAll; got != 0 {
		t.Errorf("median with no saturated session = %d, want 0", got)
	}
}

func TestSummaryAddsUpTheCollectorCounters(t *testing.T) {
	a := &Result{Stats: collector.Stats{Handled: 4, Crossed: 1,
		CrossReasons: map[string]int64{"r2_transition": 1}, Provenance: collector.ProvStats{Registered: 3, Truncated: 2}}}
	b := &Result{Stats: collector.Stats{Handled: 6, Crossed: 2,
		CrossReasons: map[string]int64{"r2_transition": 1, "provenance_edge": 1}, Provenance: collector.ProvStats{Registered: 4, Evicted: 1}}}
	s := Summarize([]*Result{a, b}, 0)
	if s.Handled != 10 || s.Crossed != 3 || s.CrossReasons["r2_transition"] != 2 || s.CrossReasons["provenance_edge"] != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.Provenance.Registered != 7 || s.Provenance.Truncated != 2 || s.Provenance.Evicted != 1 {
		t.Errorf("provenance counters = %+v", s.Provenance)
	}
}

func f64(v float64) *float64 { return &v }

func TestGate(t *testing.T) {
	good := Summarize([]*Result{resultOf(pre(tp(true), "url", 0.95), pre(tp(false), "", 0))}, 0)
	if v := (Gate{MinRecall: f64(1), MinPrecision: f64(1), MaxFPR: f64(0)}).Check(good); len(v) != 0 {
		t.Errorf("a run meeting every threshold produced violations: %v", v)
	}

	cases := []struct {
		name string
		gate Gate
		in   Summary
		want string
	}{
		{"recall below minimum", Gate{MinRecall: f64(0.9)},
			Summarize([]*Result{resultOf(pre(tp(true), "url", 0.9), pre(tp(true), "", 0))}, 0), "recall"},
		{"precision below minimum", Gate{MinPrecision: f64(0.9)},
			Summarize([]*Result{resultOf(pre(tp(true), "url", 0.9), pre(tp(false), "url", 0.9))}, 0), "precision"},
		{"false-positive rate above maximum", Gate{MaxFPR: f64(0.1)},
			Summarize([]*Result{resultOf(pre(tp(false), "url", 0.9), pre(tp(false), "", 0))}, 0), "false-positive rate"},
		{"failed assertions", Gate{},
			Summarize([]*Result{resultOf(StepResult{Produced: true, Failures: []string{"x"}})}, 0), "failing assertions"},
		{"unmodelled steps", Gate{},
			Summarize([]*Result{resultOf(StepResult{Produced: false})}, 0), "no event"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := c.gate.Check(c.in)
			if len(v) == 0 || !strings.Contains(strings.Join(v, "|"), c.want) {
				t.Errorf("violations = %v, want one mentioning %q", v, c.want)
			}
		})
	}
}

// A threshold on a metric the corpus cannot compute must fail. A corpus with its ground
// truth stripped has no hostile step, and a gate that waved it through would report green
// on a run that measured nothing.
func TestGateFailsWhenTheMetricItGatesIsUndefined(t *testing.T) {
	// Thresholds a computed zero would SATISFY (recall >= 0, precision >= 0, rate <= 1).
	// A threshold like 0.5 would not discriminate: an undefined value that leaked through
	// as 0 would fail it for the wrong reason.
	noHostile := Summarize([]*Result{resultOf(pre(nil, "", 0))}, 0)
	if v := (Gate{MinRecall: f64(0)}).Check(noHostile); len(v) == 0 {
		t.Error("-min-recall passed on a corpus with no hostile step")
	}
	if v := (Gate{MinPrecision: f64(0)}).Check(noHostile); len(v) == 0 {
		t.Error("-min-precision passed when no edge was drawn")
	}
	onlyHostile := Summarize([]*Result{resultOf(pre(tp(true), "url", 0.9))}, 0)
	if v := (Gate{MaxFPR: f64(1)}).Check(onlyHostile); len(v) == 0 {
		t.Error("-max-fpr passed on a corpus with no benign tool call")
	}
}

func TestWriteTextNamesFailuresAndWarnsAboutTheCrossedFraction(t *testing.T) {
	r := run(t, strings.Replace(exfil, `"expect":{"edge":true,"edge_class":"url","edge_from":2,"r2":"AC","crosses":true}`,
		`"expect":{"edge":false}`, 1))
	results := []*Result{r}
	var b bytes.Buffer
	WriteText(&b, results, Summarize(results, 0), false)
	out := b.String()
	for _, want := range []string{"FAIL", "exfil", "expected no provenance edge", "TP 1", "NOT\ncomparable to the M0"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report is missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTextHidesPassingStepsUnlessVerbose(t *testing.T) {
	results := []*Result{run(t, exfil)}
	var quiet, loud bytes.Buffer
	WriteText(&quiet, results, Summarize(results, 0), false)
	WriteText(&loud, results, Summarize(results, 0), true)
	if strings.Contains(quiet.String(), "step 1") {
		t.Error("a passing scenario listed its steps without -v")
	}
	if !strings.Contains(loud.String(), "step 3") || !strings.Contains(loud.String(), "edge url") {
		t.Errorf("-v should list the steps and their edges:\n%s", loud.String())
	}
}

func TestWriteJSONIsValidAndCarriesTheSummary(t *testing.T) {
	results := []*Result{run(t, exfil)}
	var b bytes.Buffer
	if err := WriteJSON(&b, results, Summarize(results, 0)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Summary struct {
			Scenarios int `json:"scenarios"`
			Confusion struct {
				TP int `json:"tp"`
			} `json:"confusion"`
		} `json:"summary"`
		Scenarios []struct {
			Steps []struct {
				EdgeClass string `json:"edge_class"`
			} `json:"steps"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Summary.Scenarios != 1 || got.Summary.Confusion.TP != 1 {
		t.Errorf("summary = %+v", got.Summary)
	}
	if len(got.Scenarios) != 1 || got.Scenarios[0].Steps[2].EdgeClass != "url" {
		t.Errorf("scenarios = %+v", got.Scenarios)
	}
}

func runResult(hostile *bool, unlabeled bool, steps ...StepResult) *Result {
	return &Result{Scenario: Header{Hostile: hostile, StepsUnlabeled: unlabeled}, Steps: steps}
}

func TestRunLevelConfusion(t *testing.T) {
	s := Summarize([]*Result{
		runResult(tp(true), true, pre(nil, "url", 0.9)),     // hostile run with an edge: TP
		runResult(tp(true), true, pre(nil, "", 0)),          // hostile run, no edge: FN
		runResult(tp(false), false, pre(nil, "email", 0.9)), // benign run with an edge: FP
		runResult(tp(false), false, pre(nil, "", 0)),        // benign run, quiet: TN
		runResult(nil, true, pre(nil, "url", 0.9)),          // no run label: left out
	}, 0)
	if s.Runs != (Confusion{TP: 1, FN: 1, FP: 1, TN: 1}) {
		t.Errorf("runs = %+v, want one of each", s.Runs)
	}
	if s.RunsUnlabeled != 1 {
		t.Errorf("RunsUnlabeled = %d, want 1", s.RunsUnlabeled)
	}
}

func TestRunLevelRespectsTheConfidenceFloor(t *testing.T) {
	r := runResult(tp(false), false, pre(nil, "domain", 0.40))
	if got := Summarize([]*Result{r}, 0).Runs; got.FP != 1 {
		t.Errorf("at floor 0: %+v, want FP", got)
	}
	if got := Summarize([]*Result{r}, 0.5).Runs; got.TN != 1 {
		t.Errorf("at floor 0.5: %+v, want the low-confidence edge not to make the run positive", got)
	}
}

// The reason steps_unlabeled exists: without it, an edge on the attacker's own call in an
// attack run would be scored as a false positive.
func TestUnlabeledStepsStayOutOfTheStepMatrix(t *testing.T) {
	s := Summarize([]*Result{
		runResult(tp(true), true, pre(nil, "url", 0.95), pre(nil, "", 0)),
		runResult(tp(false), false, pre(nil, "", 0)),
	}, 0)
	if s.Confusion != (Confusion{TN: 1}) {
		t.Errorf("step confusion = %+v; the attack run's actions must not count as benign", s.Confusion)
	}
	if s.StepsUnlabeled != 2 {
		t.Errorf("StepsUnlabeled = %d, want 2", s.StepsUnlabeled)
	}
}

func TestRunGates(t *testing.T) {
	s := Summarize([]*Result{
		runResult(tp(true), true, pre(nil, "", 0)),
		runResult(tp(false), false, pre(nil, "url", 0.9)),
	}, 0)
	if v := (Gate{MinRunRecall: f64(0.5)}).Check(s); len(v) == 0 {
		t.Error("run recall 0 passed a 0.5 minimum")
	}
	if v := (Gate{MaxRunFPR: f64(0.5)}).Check(s); len(v) == 0 {
		t.Error("run FPR 1 passed a 0.5 maximum")
	}
	// Undefined must fail even at thresholds a zero would satisfy.
	none := Summarize([]*Result{runResult(nil, false, pre(nil, "", 0))}, 0)
	if v := (Gate{MinRunRecall: f64(0)}).Check(none); len(v) == 0 {
		t.Error("-min-run-recall passed with no hostile run")
	}
	if v := (Gate{MaxRunFPR: f64(1)}).Check(none); len(v) == 0 {
		t.Error("-max-run-fpr passed with no benign run")
	}
}

func TestLargeCorporaListOnlyFailuresUnlessVerbose(t *testing.T) {
	var results []*Result
	for i := 0; i < listAllBelow+5; i++ {
		results = append(results, &Result{Scenario: Header{Name: fmt.Sprintf("s%03d", i)}, Steps: []StepResult{{Produced: true}}})
	}
	results[7].Steps[0].Failures = []string{"boom"}
	var b bytes.Buffer
	WriteText(&b, results, Summarize(results, 0), false)
	out := b.String()
	if !strings.Contains(out, "s007") || strings.Contains(out, "s008") {
		t.Errorf("want only the failing scenario listed:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("(%d passing scenarios not listed", listAllBelow+4)) {
		t.Errorf("the hidden count is missing:\n%s", out)
	}
	b.Reset()
	WriteText(&b, results, Summarize(results, 0), true)
	if !strings.Contains(b.String(), "s008") {
		t.Error("-v must list every scenario")
	}
}
