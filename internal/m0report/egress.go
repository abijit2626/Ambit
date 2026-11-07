package m0report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

var egressKind = []byte(`"kind":"egress_destination"`)

// FirstWeekDays is how long the egress profile is taken to be learning. It is a reading aid for the cohort
// review, not a threshold: whether a learning period exists, and how long, is still undecided (docs/07).
const FirstWeekDays = 7

// Egress is D9's shadow profile as the endpoint's events.jsonl shows it: how many destinations were new
// to the endpoint, when, and how. It is not an M0 criterion; it is what the cohort review reads before
// anyone writes a rule on a new destination.
type Egress struct {
	Files        []string       `json:"files"`
	Destinations int            `json:"new_destinations"`
	BySource     map[string]int `json:"by_source,omitempty"`
	Days         []EgressDay    `json:"days,omitempty"`

	// FirstWeekPerDay and LaterPerDay are means over calendar days, empty days included, from the
	// first event's day: its first FirstWeekDays days, and every day after up to the last event.
	FirstWeekPerDay float64 `json:"first_week_per_day"`
	LaterPerDay     float64 `json:"later_per_day"`
	LaterDays       int     `json:"later_days"`

	// Learning is what a rule alerting on every new destination would have fired, for each of
	// LearningPeriods; see learningRows.
	Learning []LearningRow `json:"learning,omitempty"`
}

// LearningPeriods are the learning periods the report tries, in days. Decision 3 in docs/07 is
// whether D9 alerts only after one, and how long; these rows are the evidence for it.
var LearningPeriods = []int{0, 3, 7, 14, 30}

// LearningRow is what a rule that alerts on every new destination would have fired on this endpoint
// had it stayed silent for the first Days days of the window: Alerts in all, PerDay over the
// AlertDays calendar days after the learning period up to the last event. Covered is false when the
// window ends inside the learning period, so the row says nothing yet.
type LearningRow struct {
	Days      int     `json:"days"`
	Covered   bool    `json:"covered"`
	Alerts    int     `json:"alerts"`
	AlertDays int     `json:"alert_days"`
	PerDay    float64 `json:"alerts_per_day"`
}

type EgressDay struct {
	Day          string `json:"day"`
	Destinations int    `json:"new_destinations"`
}

// EventsFiles is events.jsonl and its rotated copies, the SIEM-bound sink where egress_destination lives.
func EventsFiles(eventsPath string) ([]string, error) {
	return SpoolFiles(eventsPath)
}

// BuildEgress reads egress_destination events from files. A line that is not one is skipped without
// being parsed, as health lines are in the spool.
func BuildEgress(files []string) (*Egress, error) {
	g := &Egress{Files: files, BySource: map[string]int{}}
	perDay := map[string]int{}
	for _, path := range files {
		if err := scanEgress(path, g, perDay); err != nil {
			return nil, err
		}
	}
	if len(perDay) == 0 {
		g.BySource = nil
		return g, nil
	}
	days := make([]string, 0, len(perDay))
	for d := range perDay {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, d := range days {
		g.Days = append(g.Days, EgressDay{Day: d, Destinations: perDay[d]})
	}

	first, _ := time.Parse(time.DateOnly, days[0])
	last, _ := time.Parse(time.DateOnly, days[len(days)-1])
	span := int(last.Sub(first).Hours()/24) + 1
	weekDays := min(span, FirstWeekDays)
	week, later := 0, 0
	for d, n := range perDay {
		t, _ := time.Parse(time.DateOnly, d)
		if int(t.Sub(first).Hours()/24) < FirstWeekDays {
			week += n
		} else {
			later += n
		}
	}
	g.FirstWeekPerDay = float64(week) / float64(weekDays)
	if g.LaterDays = span - weekDays; g.LaterDays > 0 {
		g.LaterPerDay = float64(later) / float64(g.LaterDays)
	}
	g.Learning = learningRows(perDay, first, span)
	return g, nil
}

// learningRows counts, for each learning period, the new destinations after it. The window starts on
// the first egress_destination's day, which is close to when the profile started: an empty profile
// reports its first destinations as soon as anything is contacted.
func learningRows(perDay map[string]int, first time.Time, span int) []LearningRow {
	rows := make([]LearningRow, 0, len(LearningPeriods))
	for _, l := range LearningPeriods {
		row := LearningRow{Days: l, Covered: span > l, AlertDays: max(span-l, 0)}
		for d, n := range perDay {
			t, _ := time.Parse(time.DateOnly, d)
			if int(t.Sub(first).Hours()/24) >= l {
				row.Alerts += n
			}
		}
		if row.AlertDays > 0 {
			row.PerDay = float64(row.Alerts) / float64(row.AlertDays)
		}
		rows = append(rows, row)
	}
	return rows
}

func scanEgress(path string, g *Egress, perDay map[string]int) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && bytes.Contains(line, egressKind) {
			var e struct {
				TS     string `json:"ts"`
				Source string `json:"egress_source"`
			}
			if json.Unmarshal(line, &e) == nil && len(e.TS) >= len(time.DateOnly) {
				if t, perr := time.Parse(time.RFC3339Nano, e.TS); perr == nil {
					perDay[t.UTC().Format(time.DateOnly)]++
					g.Destinations++
					src := e.Source
					if src == "" {
						src = "unknown"
					}
					g.BySource[src]++
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read %s: %w", path, err)
		}
	}
}

func (g *Egress) writeText(p func(string, ...any)) {
	p("D9 new destinations (shadow; not an M0 criterion)")
	if g.Destinations == 0 {
		p("  no egress_destination events in %d file(s); D9's profile may be off, or nothing new was contacted", len(g.Files))
		return
	}
	p("  %d new destinations over %d day(s) with any; bash %d, script %d, sandbox %d", g.Destinations, len(g.Days), g.BySource["bash"], g.BySource["script"], g.BySource["sandbox"])
	if g.LaterDays > 0 {
		p("  first %d days: %.1f a day   after: %.1f a day over %d day(s)", FirstWeekDays, g.FirstWeekPerDay, g.LaterPerDay, g.LaterDays)
	} else {
		p("  %.1f a day; the window is inside the first %d days, so there is no later rate yet", g.FirstWeekPerDay, FirstWeekDays)
	}
	if len(g.Learning) > 0 {
		p("  a rule alerting on each new destination, silent for a learning period of:")
		for _, r := range g.Learning {
			if !r.Covered {
				p("    %2d days: the window ends inside it; no evidence yet", r.Days)
				continue
			}
			p("    %2d days: %d alert(s), %.1f a day over %d day(s)", r.Days, r.Alerts, r.PerDay, r.AlertDays)
		}
	}
}
