// Package m0report is `ambitd report`: the M0 exit-criteria readout for one endpoint, computed
// from the ambitd_health events in the local trajectory spool.
//
// Every health event carries counters that are cumulative for the run that wrote it, so the
// report keeps the last health event of each run and sums across runs. That survives restarts,
// and a run's final event (written on a clean shutdown) closes its last interval. What it cannot
// see is a run whose every health event has been rotated out of the spool, so it says when the
// spool has deleted files.
package m0report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/abijit2626/ambit/internal/config"
	"github.com/abijit2626/ambit/internal/event"
	"github.com/abijit2626/ambit/internal/runstate"
	"github.com/abijit2626/ambit/internal/sink"
)

const (
	LatencyCriterion = 0.01
	LossCriterion    = 0.001
	DesignFracLow    = 0.02
	DesignFracHigh   = 0.05

	maxHealthLine = 1 << 20
)

const (
	Pass   = "pass"
	Fail   = "fail"
	NoData = "no_data"
)

var healthKind = []byte(`"kind":"ambitd_health"`)

type Run struct {
	RunID      string         `json:"run_id"`
	Version    string         `json:"version,omitempty"`
	First      string         `json:"first"`
	Last       string         `json:"last"`
	UptimeSec  int64          `json:"uptime_sec"`
	Final      bool           `json:"final"`
	Heartbeats int            `json:"heartbeats"`
	PrevRun    *event.PrevRun `json:"prev_run,omitempty"`

	health       event.Health
	firstT, last time.Time
}

type Latency struct {
	Verdict            string  `json:"verdict"`
	Responses          int64   `json:"responses"`
	OverBudget         int64   `json:"over_budget"`
	OverBudgetFrac     float64 `json:"over_budget_fraction"`
	BudgetUS           int64   `json:"budget_us"`
	MixedBudgets       bool    `json:"mixed_budgets,omitempty"`
	P50US              int64   `json:"p50_us"`
	P95US              int64   `json:"p95_us"`
	P99US              int64   `json:"p99_us"`
	MaxUS              int64   `json:"max_us"`
	Criterion          float64 `json:"criterion_over_budget_fraction"`
	RunsWithoutLatency int     `json:"runs_without_latency,omitempty"`
}

type Loss struct {
	Verdict     string  `json:"verdict"`
	Written     int64   `json:"trajectory_written"`
	Dropped     int64   `json:"dropped"`
	WriteErrors int64   `json:"write_errors"`
	ParseErrors int64   `json:"parse_errors"`
	Lost        int64   `json:"lost"`
	Fraction    float64 `json:"fraction"`
	Criterion   float64 `json:"criterion_fraction"`
}

type Restarts struct {
	Restarts     int   `json:"restarts"`
	Unclean      int   `json:"unclean"`
	Unknown      int   `json:"unknown"`
	DownSec      int64 `json:"down_sec"`
	OpenRunFinal bool  `json:"latest_run_stopped_cleanly"`
}

type Fraction struct {
	ToolCalls   int64   `json:"tool_calls"`
	ToolCrossed int64   `json:"tool_crossed"`
	Fraction    float64 `json:"fraction"`
	InDesign    bool    `json:"within_design_estimate"`

	Handled     int64   `json:"all_handled"`
	Crossed     int64   `json:"all_crossed"`
	AllFraction float64 `json:"all_fraction"`
}

type Report struct {
	Files         []string `json:"files"`
	EndpointID    string   `json:"endpoint_id,omitempty"`
	WindowStart   string   `json:"window_start,omitempty"`
	WindowEnd     string   `json:"window_end,omitempty"`
	Runs          []Run    `json:"runs"`
	LegacyHealth  int      `json:"legacy_health_events,omitempty"`
	Unreadable    int      `json:"unreadable_health_lines,omitempty"`
	RetiredFiles  int64    `json:"trajectory_retired_files"`
	Latency       Latency  `json:"latency"`
	Loss          Loss     `json:"loss"`
	Restarts      Restarts `json:"restarts"`
	Interesting   Fraction `json:"interesting_fraction"`
	NotMeasurable []string `json:"not_measured_here"`
}

var notMeasurable = []string{
	"cohort size: the Wazuh agent list for the cohort's group",
	"developer-visible behavior change: ask each volunteer, and diff their permissions and sandbox settings",
	`"Too many fields for JSON decoder": grep -i "too many fields" /var/ossec/logs/ossec.log on the manager`,
}

func SpoolFiles(trajectoryPath string) ([]string, error) {
	rotated, err := sink.RotatedFiles(trajectoryPath)
	if err != nil {
		return nil, err
	}
	var files []string
	if _, err := os.Stat(trajectoryPath); err == nil {
		files = append(files, trajectoryPath)
	}
	return append(files, rotated...), nil
}

func Build(files []string) (*Report, error) {
	r := &Report{Files: files, NotMeasurable: notMeasurable}
	byRun := map[string]*Run{}
	for _, path := range files {
		if err := r.scan(path, byRun); err != nil {
			return nil, err
		}
	}
	for _, run := range byRun {
		run.First = run.firstT.UTC().Format(time.RFC3339Nano)
		run.Last = run.last.UTC().Format(time.RFC3339Nano)
		r.Runs = append(r.Runs, *run)
	}
	sort.Slice(r.Runs, func(i, j int) bool { return r.Runs[i].firstT.Before(r.Runs[j].firstT) })
	r.summarize()
	return r, nil
}

func (r *Report) scan(path string, byRun map[string]*Run) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, maxHealthLine)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && err != io.EOF {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if err == io.EOF {
				return nil
			}
			continue
		}
		if len(line) > 0 && bytes.Contains(line, healthKind) {
			r.add(line, byRun)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
	}
}

func (r *Report) add(line []byte, byRun map[string]*Run) {
	var e event.Event
	if json.Unmarshal(line, &e) != nil || e.Kind != event.KindAmbitdHealth || e.Health == nil {
		r.Unreadable++
		return
	}
	h := e.Health
	if h.RunID == "" {
		r.LegacyHealth++
		return
	}
	if r.EndpointID == "" {
		r.EndpointID = e.Endpoint.EndpointID
	}
	ts, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		r.Unreadable++
		return
	}
	run, ok := byRun[h.RunID]
	if !ok {
		run = &Run{RunID: h.RunID, firstT: ts}
		byRun[h.RunID] = run
	}
	run.Heartbeats++
	if ts.Before(run.firstT) {
		run.firstT = ts
	}
	if run.Final && !h.Final {
		return
	}
	if h.Final || !ts.Before(run.last) {
		run.last = ts
		run.UptimeSec = h.UptimeSec
		run.Version = e.Endpoint.AmbitdVersion
		run.Final = h.Final
		run.PrevRun = h.PrevRun
		run.health = *h
	}
}

func (r *Report) summarize() {
	var lats []event.Latency
	var withLatency int
	var end time.Time
	for i, run := range r.Runs {
		h := run.health
		if i == 0 {
			r.WindowStart = run.First
		}
		if run.last.After(end) {
			end = run.last
			r.WindowEnd = run.Last
		}
		if h.HookLatency != nil {
			lats = append(lats, *h.HookLatency)
			withLatency++
		}
		r.Loss.Written += h.TrajectoryWritten
		r.Loss.Dropped += h.DroppedEvents
		r.Loss.WriteErrors += h.WriteErrors
		r.Loss.ParseErrors += h.ParseErrors
		r.Interesting.Handled += h.Handled
		r.Interesting.Crossed += h.Crossed
		r.Interesting.ToolCalls += h.ToolCalls
		r.Interesting.ToolCrossed += h.ToolCrossed
		if h.TrajectoryRetired > r.RetiredFiles {
			r.RetiredFiles = h.TrajectoryRetired
		}
		if p := run.PrevRun; p != nil {
			r.Restarts.Restarts++
			r.Restarts.DownSec += p.DownSec
			switch p.Stop {
			case runstate.StopUnclean:
				r.Restarts.Unclean++
			case runstate.StopUnknown:
				r.Restarts.Unknown++
			}
		}
		if i == len(r.Runs)-1 {
			r.Restarts.OpenRunFinal = run.Final
		}
	}

	m, same := event.MergeLatency(lats...)
	r.Latency = Latency{
		Responses:          m.Count,
		OverBudget:         m.OverBudget,
		BudgetUS:           m.BudgetUS,
		MixedBudgets:       !same,
		P50US:              m.P50US,
		P95US:              m.P95US,
		P99US:              m.P99US,
		MaxUS:              m.MaxUS,
		Criterion:          LatencyCriterion,
		RunsWithoutLatency: len(r.Runs) - withLatency,
		Verdict:            NoData,
	}
	if m.Count > 0 {
		r.Latency.OverBudgetFrac = float64(m.OverBudget) / float64(m.Count)
		r.Latency.Verdict = verdict(r.Latency.OverBudgetFrac < LatencyCriterion)
	}

	l := &r.Loss
	l.Lost = l.Dropped + l.WriteErrors + l.ParseErrors
	l.Criterion = LossCriterion
	l.Verdict = NoData
	if total := l.Written + l.Lost; total > 0 {
		l.Fraction = float64(l.Lost) / float64(total)
		l.Verdict = verdict(l.Fraction < LossCriterion)
	}

	f := &r.Interesting
	if f.ToolCalls > 0 {
		f.Fraction = float64(f.ToolCrossed) / float64(f.ToolCalls)
		f.InDesign = f.Fraction >= DesignFracLow && f.Fraction <= DesignFracHigh
	}
	if f.Handled > 0 {
		f.AllFraction = float64(f.Crossed) / float64(f.Handled)
	}
}

func verdict(ok bool) string {
	if ok {
		return Pass
	}
	return Fail
}

func (r *Report) WriteText(w io.Writer, verbose bool) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("ambitd M0 report")
	if r.EndpointID != "" {
		p("  endpoint:   %s", r.EndpointID)
	}
	if len(r.Runs) == 0 {
		p("  no health events with a run id in %s", strings.Join(r.Files, ", "))
		if r.LegacyHealth > 0 {
			p("  %d health events came from an ambitd too old to report; upgrade and collect again", r.LegacyHealth)
		}
		return
	}
	p("  window:     %s to %s (%s), %d run(s)", r.WindowStart, r.WindowEnd, span(r.WindowStart, r.WindowEnd), len(r.Runs))
	if r.RetiredFiles > 0 {
		p("  WARNING:    the spool has deleted %d file(s) at its retention cap; runs older than the window are missing", r.RetiredFiles)
	}
	if r.LegacyHealth > 0 {
		p("  note:       %d health events from an older ambitd carry no run id and are not counted", r.LegacyHealth)
	}
	p("")

	lt := r.Latency
	p("p99 hook response under %s                          [%s]", us(lt.BudgetUS), strings.ToUpper(lt.Verdict))
	if lt.Responses > 0 {
		p("  %d responses, %d over budget (%.3f%%; passes under %.0f%%)", lt.Responses, lt.OverBudget, lt.OverBudgetFrac*100, LatencyCriterion*100)
		p("  p50 <= %s   p95 <= %s   p99 <= %s   max %s", us(lt.P50US), us(lt.P95US), us(lt.P99US), us(lt.MaxUS))
		p("  timed inside the handler: excludes the client's connect time")
	}
	if lt.MixedBudgets {
		p("  WARNING: runs used different latency budgets, so over-budget counts do not share a threshold")
	}
	if lt.RunsWithoutLatency > 0 {
		p("  %d run(s) carry no latency data", lt.RunsWithoutLatency)
	}
	p("")

	l := r.Loss
	p("spool event loss under %.1f%%                              [%s]", LossCriterion*100, strings.ToUpper(l.Verdict))
	p("  %d written, %d lost (%.4f%%): %d dropped on a full queue, %d write errors, %d unparseable hook bodies",
		l.Written, l.Lost, l.Fraction*100, l.Dropped, l.WriteErrors, l.ParseErrors)
	p("  not counted as loss: events Claude Code sent while ambitd was down (see restarts)")
	p("")

	rs := r.Restarts
	p("restarts")
	p("  %d restart(s): %d after an unclean stop, %d unknown; %s down in total (an upper bound)", rs.Restarts, rs.Unclean, rs.Unknown, (time.Duration(rs.DownSec) * time.Second).String())
	if !rs.OpenRunFinal {
		p("  the latest run has no final event: it is still running, or it stopped uncleanly")
	}
	p("")

	f := r.Interesting
	p("interesting fraction (measured, not pass/fail; design estimate %.0f-%.0f%% of tool calls)", DesignFracLow*100, DesignFracHigh*100)
	if f.ToolCalls > 0 {
		note := "within"
		if !f.InDesign {
			note = "outside"
		}
		p("  %d of %d hook tool events crossed to Wazuh: %.2f%%, %s the estimate", f.ToolCrossed, f.ToolCalls, f.Fraction*100, note)
		if !f.InDesign && f.Fraction > DesignFracHigh {
			p("  above the estimate: tighten the filter criteria in docs/04-data-model.md before M1")
		}
	} else {
		p("  no tool events yet")
	}
	if f.Handled > 0 {
		p("  all events: %d of %d crossed (%.2f%%), which includes prompts, session starts and interposer reports", f.Crossed, f.Handled, f.AllFraction*100)
	}
	p("")

	p("measured elsewhere")
	for _, s := range r.NotMeasurable {
		p("  %s", s)
	}

	if verbose {
		p("")
		p("runs")
		for _, run := range r.Runs {
			stop := "running or unclean"
			if run.Final {
				stop = "clean"
			}
			prev := "first run"
			if run.PrevRun != nil {
				prev = fmt.Sprintf("after %s stop, %ds down", run.PrevRun.Stop, run.PrevRun.DownSec)
			}
			p("  %s  %s  %s to %s  %d heartbeats  end: %s  start: %s", run.RunID, run.Version, run.First, run.Last, run.Heartbeats, stop, prev)
		}
	}
}

func span(a, b string) string {
	ta, err1 := time.Parse(time.RFC3339Nano, a)
	tb, err2 := time.Parse(time.RFC3339Nano, b)
	if err1 != nil || err2 != nil {
		return "?"
	}
	return tb.Sub(ta).Round(time.Second).String()
}

func us(v int64) string {
	switch {
	case v >= 1000000:
		return fmt.Sprintf("%.1fs", float64(v)/1e6)
	case v >= 1000:
		return fmt.Sprintf("%.1fms", float64(v)/1e3)
	}
	return fmt.Sprintf("%dus", v)
}

func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "ambitd config JSON to read trajectory_path from")
	traj := fs.String("trajectory", "", "trajectory spool to read; default is trajectory_path from -config")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	verbose := fs.Bool("v", false, "list every run")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	path := *traj
	if path == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, "ambitd report:", err)
			return 1
		}
		path = cfg.TrajectoryPath
	}
	files, err := SpoolFiles(path)
	if err != nil {
		fmt.Fprintln(stderr, "ambitd report:", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintf(stderr, "ambitd report: no spool at %s\n", path)
		return 1
	}
	r, err := Build(files)
	if err != nil {
		fmt.Fprintln(stderr, "ambitd report:", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(stderr, "ambitd report:", err)
			return 1
		}
		return 0
	}
	r.WriteText(stdout, *verbose)
	return 0
}
