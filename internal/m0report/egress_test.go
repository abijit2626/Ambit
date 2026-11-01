package m0report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func egressLine(day int, hour int, source string) string {
	return fmt.Sprintf(`{"schema_v":2,"ts":"2026-11-%02dT%02d:00:00Z","kind":"egress_destination","egress_source":%q,"egress_dest_digest":"hmac:x"}`, day, hour, source)
}

func writeEvents(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEgressSummaryCountsDaysAndRates(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, egressLine(1, i, "bash"))
	}
	lines = append(lines,
		egressLine(2, 1, "bash"), egressLine(2, 2, "bash"), egressLine(2, 3, "sandbox"),
		`{"kind":"tool_pre","ts":"2026-11-03T00:00:00Z"}`,
		`{"kind":"egress_destination","ts":"not a time"}`,
		`not json "kind":"egress_destination"`,
		egressLine(9, 1, "bash"),
		egressLine(10, 1, "sandbox"),
	)
	g, err := BuildEgress([]string{writeEvents(t, lines...)})
	if err != nil {
		t.Fatal(err)
	}
	if g.Destinations != 10 || g.BySource["bash"] != 8 || g.BySource["sandbox"] != 2 {
		t.Fatalf("counts = %d, %v; want 10 new destinations, 8 bash and 2 sandbox", g.Destinations, g.BySource)
	}
	if len(g.Days) != 4 || g.Days[0].Day != "2026-11-01" || g.Days[0].Destinations != 5 {
		t.Errorf("days = %+v", g.Days)
	}
	// Days 1-7 hold 8 destinations over 7 calendar days; days 8-10 hold 2 over 3, day 8 being empty.
	if g.FirstWeekPerDay != 8.0/7 || g.LaterDays != 3 || g.LaterPerDay != 2.0/3 {
		t.Errorf("rates: first week %.3f, later %.3f over %d days; want %.3f and %.3f over 3",
			g.FirstWeekPerDay, g.LaterPerDay, g.LaterDays, 8.0/7, 2.0/3)
	}
}

func TestEgressSummaryInsideTheFirstWeek(t *testing.T) {
	g, err := BuildEgress([]string{writeEvents(t, egressLine(1, 1, "bash"), egressLine(3, 1, "bash"))})
	if err != nil {
		t.Fatal(err)
	}
	if g.FirstWeekPerDay != 2.0/3 || g.LaterDays != 0 || g.LaterPerDay != 0 {
		t.Errorf("a three-day window: first week %.3f, later %.3f over %d days", g.FirstWeekPerDay, g.LaterPerDay, g.LaterDays)
	}
	var buf bytes.Buffer
	g.writeText(func(f string, a ...any) { fmt.Fprintf(&buf, f+"\n", a...) })
	if !strings.Contains(buf.String(), "no later rate yet") {
		t.Errorf("text = %s", buf.String())
	}
}

func TestEgressSummaryWithNothingSaysSo(t *testing.T) {
	g, err := BuildEgress([]string{writeEvents(t, `{"kind":"tool_pre"}`), filepath.Join(t.TempDir(), "absent")})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	g.writeText(func(f string, a ...any) { fmt.Fprintf(&buf, f+"\n", a...) })
	if g.Destinations != 0 || !strings.Contains(buf.String(), "no egress_destination events") {
		t.Errorf("summary = %+v, text = %s", g, buf.String())
	}
}

func TestMainReadsEgressFromTheEventsFile(t *testing.T) {
	spool := twoRunSpool(t)
	events := writeEvents(t, egressLine(1, 1, "bash"), egressLine(1, 2, "sandbox"))
	var out, errOut bytes.Buffer
	if code := Main([]string{"-trajectory", spool, "-events", events}, &out, &errOut); code != 0 {
		t.Fatalf("Main = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "D9 new destinations") || !strings.Contains(out.String(), "2 new destinations") {
		t.Errorf("report lacks the D9 section:\n%s", out.String())
	}
}
