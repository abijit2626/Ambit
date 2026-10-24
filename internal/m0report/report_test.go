package m0report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abijit2626/ambit/internal/event"
)

var t0 = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

func health(at time.Time, h event.Health) *event.Event {
	return &event.Event{
		EventID: "health", TS: at.Format(time.RFC3339Nano), Source: event.SourceAmbitd,
		SchemaV: event.SchemaVersion, Kind: event.KindAmbitdHealth,
		Endpoint: event.Endpoint{EndpointID: "ep_1", AmbitdVersion: "v1"},
		Health:   &h,
	}
}

func lat(count, over int64, buckets map[int64]int64, max int64) *event.Latency {
	l := &event.Latency{Count: count, OverBudget: over, BudgetUS: 5000, MaxUS: max}
	for _, le := range []int64{500, 5000, 25000} {
		l.Buckets = append(l.Buckets, event.LatencyBucket{LEUS: le, N: buckets[le]})
	}
	return l
}

func writeLines(t *testing.T, path string, lines ...any) {
	t.Helper()
	var buf bytes.Buffer
	for _, l := range lines {
		switch v := l.(type) {
		case string:
			buf.WriteString(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(b)
		}
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func twoRunSpool(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	traj := filepath.Join(dir, "trajectory.jsonl")

	writeLines(t, traj+".1",
		`{"kind":"tool_pre","session":{"session_id":"s1"}}`,
		health(t0.Add(-time.Hour), event.Health{Status: "ok"}),
		health(t0, event.Health{RunID: "r1", Handled: 10, Crossed: 1, ToolCalls: 8, ToolCrossed: 0, TrajectoryWritten: 20,
			HookLatency: lat(10, 0, map[int64]int64{500: 10}, 300)}),
		health(t0.Add(time.Minute), event.Health{RunID: "r1", Handled: 100, Crossed: 3, ToolCalls: 80, ToolCrossed: 2, TrajectoryWritten: 200,
			HookLatency: lat(100, 1, map[int64]int64{500: 99, 25000: 1}, 9000)}),
	)
	writeLines(t, traj,
		`{"kind":"tool_pre","pad":"`+strings.Repeat("x", maxHealthLine+10)+`","note":"\"kind\":\"ambitd_health\""}`,
		health(t0.Add(10*time.Minute), event.Health{RunID: "r2", Handled: 900, Crossed: 36, ToolCalls: 720, ToolCrossed: 25, TrajectoryWritten: 1800,
			DroppedEvents: 1, ParseErrors: 1, TrajectoryRetired: 2,
			PrevRun:     &event.PrevRun{RunID: "r1", Stop: "unclean", DownSec: 480},
			HookLatency: lat(900, 2, map[int64]int64{500: 890, 5000: 8, 25000: 2}, 12000)}),
		`{"kind":"ambitd_health",`,
		health(t0.Add(11*time.Minute), event.Health{RunID: "r2", Final: true, Handled: 900, Crossed: 36, ToolCalls: 720, ToolCrossed: 25, TrajectoryWritten: 1801,
			DroppedEvents: 1, ParseErrors: 1, TrajectoryRetired: 2,
			PrevRun:     &event.PrevRun{RunID: "r1", Stop: "unclean", DownSec: 480},
			HookLatency: lat(900, 2, map[int64]int64{500: 890, 5000: 8, 25000: 2}, 12000)}),
	)
	return traj
}

func build(t *testing.T, traj string) *Report {
	t.Helper()
	files, err := SpoolFiles(traj)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Build(files)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportSumsTheLastHealthEventOfEachRun(t *testing.T) {
	r := build(t, twoRunSpool(t))

	if len(r.Runs) != 2 || r.Runs[0].RunID != "r1" || r.Runs[1].RunID != "r2" {
		t.Fatalf("runs = %+v, want r1 then r2", r.Runs)
	}
	if r.Runs[0].Heartbeats != 2 || r.Runs[1].Heartbeats != 2 {
		t.Errorf("heartbeats = %d, %d, want 2 and 2", r.Runs[0].Heartbeats, r.Runs[1].Heartbeats)
	}
	if r.LegacyHealth != 1 {
		t.Errorf("legacy = %d, want 1", r.LegacyHealth)
	}
	if r.Unreadable != 1 {
		t.Errorf("unreadable = %d, want 1: the truncated health line", r.Unreadable)
	}
	if r.Latency.Responses != 1000 || r.Latency.OverBudget != 3 {
		t.Errorf("latency = %+v, want 1000 responses and 3 over budget: r1's last plus r2's last, not every heartbeat", r.Latency)
	}
	if r.Latency.Verdict != Pass {
		t.Errorf("latency verdict = %s, want pass at 0.3%% over budget", r.Latency.Verdict)
	}
	if r.Latency.MaxUS != 12000 {
		t.Errorf("max = %d", r.Latency.MaxUS)
	}
	if r.Loss.Written != 2001 || r.Loss.Lost != 2 {
		t.Errorf("loss = %+v, want 2001 written (r2's final, not its earlier beat) and 2 lost", r.Loss)
	}
	if r.Loss.Verdict != Pass {
		t.Errorf("loss verdict = %s, want pass: 2 of 2003 is 0.0999%%", r.Loss.Verdict)
	}
	if r.Restarts.Restarts != 1 || r.Restarts.Unclean != 1 || r.Restarts.DownSec != 480 || !r.Restarts.OpenRunFinal {
		t.Errorf("restarts = %+v", r.Restarts)
	}
	if f := r.Interesting; f.ToolCalls != 800 || f.ToolCrossed != 27 || !f.InDesign {
		t.Errorf("interesting = %+v, want 27 of 800 tool events, inside 2-5%%", f)
	}
	if f := r.Interesting; f.Handled != 1000 || f.Crossed != 39 {
		t.Errorf("all events = %d of %d, want 39 of 1000", f.Crossed, f.Handled)
	}
	if r.RetiredFiles != 2 {
		t.Errorf("retired = %d", r.RetiredFiles)
	}
	if r.WindowStart != t0.Format(time.RFC3339Nano) || r.WindowEnd != t0.Add(11*time.Minute).Format(time.RFC3339Nano) {
		t.Errorf("window = %s to %s", r.WindowStart, r.WindowEnd)
	}
}

func TestReportLatencyFailsAtOnePercentOverBudget(t *testing.T) {
	traj := filepath.Join(t.TempDir(), "trajectory.jsonl")
	writeLines(t, traj, health(t0, event.Health{RunID: "r1",
		HookLatency: lat(100, 1, map[int64]int64{500: 99, 25000: 1}, 9000)}))
	if v := build(t, traj).Latency.Verdict; v != Fail {
		t.Errorf("verdict = %s, want fail: the criterion is under 1%%, and 1 of 100 is not under it", v)
	}
}

func TestReportLossFailsAtOneInAThousand(t *testing.T) {
	traj := filepath.Join(t.TempDir(), "trajectory.jsonl")
	writeLines(t, traj, health(t0, event.Health{RunID: "r1", TrajectoryWritten: 999, WriteErrors: 1}))
	if v := build(t, traj).Loss.Verdict; v != Fail {
		t.Errorf("verdict = %s, want fail: 1 lost of 1000 is 0.1%%, not under it", v)
	}
}

func TestReportWithNoRunsSaysSo(t *testing.T) {
	traj := filepath.Join(t.TempDir(), "trajectory.jsonl")
	writeLines(t, traj, health(t0, event.Health{Status: "ok"}))
	r := build(t, traj)
	if r.Latency.Verdict != NoData || r.Loss.Verdict != NoData {
		t.Errorf("verdicts = %s, %s, want no_data", r.Latency.Verdict, r.Loss.Verdict)
	}
	var out bytes.Buffer
	r.WriteText(&out, false)
	if !strings.Contains(out.String(), "too old to report") {
		t.Errorf("text does not explain the legacy events:\n%s", out.String())
	}
}

func TestReportTextNamesEveryCriterionAndTheRetentionWarning(t *testing.T) {
	var out bytes.Buffer
	build(t, twoRunSpool(t)).WriteText(&out, true)
	s := out.String()
	for _, want := range []string{
		"p99 hook response under 5.0ms", "[PASS]",
		"spool event loss under 0.1%",
		"1 restart(s): 1 after an unclean stop",
		"27 of 800 hook tool events crossed",
		"all events: 39 of 1000 crossed",
		"WARNING:    the spool has deleted 2 file(s)",
		"too many fields",
		"r1  v1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("text is missing %q:\n%s", want, s)
		}
	}
}

func TestMainJSONReadsTheSpoolAndItsRotatedFiles(t *testing.T) {
	traj := twoRunSpool(t)
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"-trajectory", traj, "-json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var r Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout.String())
	}
	if len(r.Files) != 2 || len(r.Runs) != 2 {
		t.Errorf("files = %v, runs = %d", r.Files, len(r.Runs))
	}
}

func TestMainWithNoSpoolFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"-trajectory", filepath.Join(t.TempDir(), "trajectory.jsonl")}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "no spool") {
		t.Errorf("exit %d, stderr %q: want a failure naming the missing spool", code, stderr.String())
	}
}

func hookEvent(at time.Time, kind event.Kind, sid string) *event.Event {
	return &event.Event{TS: at.Format(time.RFC3339Nano), Source: event.SourceHook, Kind: kind, Session: event.Session{SessionID: sid}}
}

func TestReportCountsSessionsThatSentNothingAfterTheirStart(t *testing.T) {
	traj := filepath.Join(t.TempDir(), "trajectory.jsonl")
	writeLines(t, traj,
		hookEvent(t0, event.KindSessionStart, "silent"),
		hookEvent(t0, event.KindSessionStart, "fine"),
		hookEvent(t0.Add(time.Second), event.KindPromptSubmit, "fine"),
		hookEvent(t0.Add(time.Minute), event.KindSessionEnd, "silent"),
		hookEvent(t0.Add(9*time.Minute), event.KindSessionStart, "just-started"),
		hookEvent(t0.Add(10*time.Minute), event.KindPromptSubmit, "no-start-seen"),
		health(t0.Add(10*time.Minute), event.Health{RunID: "r1"}),
	)
	r := build(t, traj)
	if r.Sessions.Started != 3 || r.Sessions.Silent != 1 {
		t.Errorf("sessions = %+v, want 3 started and 1 silent: a session end is not a hook that got through, and one started a minute ago may still be waiting for its prompt", r.Sessions)
	}
	var out bytes.Buffer
	r.WriteText(&out, false)
	if !strings.Contains(out.String(), "blocker 7") {
		t.Errorf("text does not point at blocker 7:\n%s", out.String())
	}
}

// The spool is ambitd's own output, but it can be truncated, rotated mid-line or hand-edited; the
// report must never panic on it, and its verdicts stay in their vocabulary.
func FuzzBuildFromAnySpool(f *testing.F) {
	f.Add([]byte(`{"kind":"ambitd_health","ts":"2026-10-24T09:00:00Z","health":{"run_id":"r1","hook_latency":{"count":1,"buckets":[{"le_us":250,"n":1}]}}}` + "\n"))
	f.Add([]byte(`{"kind":"session_start","source":"hook","ts":"x","session":{"session_id":"s"}}` + "\n{\"kind\":\"ambitd_health\""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(t.TempDir(), "trajectory.jsonl")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := Build([]string{p})
		if err != nil {
			return
		}
		for _, v := range []string{r.Latency.Verdict, r.Loss.Verdict} {
			if v != Pass && v != Fail && v != NoData {
				t.Fatalf("verdict %q is not pass, fail or no_data", v)
			}
		}
		var out bytes.Buffer
		r.WriteText(&out, true)
	})
}
