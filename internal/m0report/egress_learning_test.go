package m0report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// The learning-period rows count the destinations after each period, over the days after it.
func TestEgressLearningPeriods(t *testing.T) {
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, egressLine(1, i, "bash")) // day 0: the profile's first contacts
	}
	lines = append(lines,
		egressLine(2, 1, "bash"), egressLine(3, 1, "bash"), // days 1 and 2
		egressLine(5, 1, "sandbox"), // day 4
		egressLine(9, 1, "bash"),    // day 8
		egressLine(10, 1, "bash"),   // day 9: the window is 10 days long
	)
	g, err := BuildEgress([]string{writeEvents(t, lines...)})
	if err != nil {
		t.Fatal(err)
	}
	want := []LearningRow{
		{Days: 0, Covered: true, Alerts: 11, AlertDays: 10, PerDay: 1.1},
		{Days: 3, Covered: true, Alerts: 3, AlertDays: 7, PerDay: 3.0 / 7},
		{Days: 7, Covered: true, Alerts: 2, AlertDays: 3, PerDay: 2.0 / 3},
		{Days: 14, Covered: false},
		{Days: 30, Covered: false},
	}
	if len(g.Learning) != len(want) {
		t.Fatalf("rows = %+v", g.Learning)
	}
	for i, w := range want {
		if g.Learning[i] != w {
			t.Errorf("row %d = %+v, want %+v", i, g.Learning[i], w)
		}
	}
	var buf bytes.Buffer
	g.writeText(func(f string, a ...any) { fmt.Fprintf(&buf, f+"\n", a...) })
	for _, s := range []string{" 3 days: 3 alert(s), 0.4 a day over 7 day(s)", "14 days: the window ends inside it"} {
		if !strings.Contains(buf.String(), s) {
			t.Errorf("text lacks %q:\n%s", s, buf.String())
		}
	}
}
