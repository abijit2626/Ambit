package replay

import (
	"testing"
)

const corpusDir = "../../testdata/replay"

func loadCorpus(t *testing.T) []*Scenario {
	t.Helper()
	scs, err := Load(corpusDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	return scs
}

// TestCorpus is the regression suite. Every scenario's assertions describe what the
// pipeline does today, known misses and false positives included, so a change in either
// direction fails here until somebody looks at it and updates the corpus on purpose.
func TestCorpus(t *testing.T) {
	scs := loadCorpus(t)
	var results []*Result
	for _, sc := range scs {
		r := Run(sc, Options{Config: DefaultConfig()})
		results = append(results, r)
		t.Run(sc.Name, func(t *testing.T) {
			for _, st := range r.Steps {
				for _, f := range st.Failures {
					t.Errorf("step %d (line %d): %s", st.N, st.Line, f)
				}
			}
		})
	}

	s := Summarize(results, 0)
	if s.Ignored != 0 {
		t.Errorf("%d corpus step(s) produced no event; a misspelled hook name asserts nothing", s.Ignored)
	}
	// A corpus that cannot compute a metric cannot regress it.
	c := s.Confusion
	if c.Hostile() == 0 || c.Benign() == 0 {
		t.Fatalf("corpus has %d hostile and %d benign tool calls; both are needed for precision and recall to mean anything",
			c.Hostile(), c.Benign())
	}
	if c.TP == 0 {
		t.Error("the corpus catches nothing, which is a broken engine or a broken corpus")
	}
	t.Logf("corpus: TP %d FP %d FN %d TN %d", c.TP, c.FP, c.FN, c.TN)
}

// The tags are documentation that a reader will trust, so they are checked against the
// scenarios they describe.
func TestCorpusTagsMatchWhatTheScenariosActuallyDo(t *testing.T) {
	has := func(sc *Scenario, tag string) bool {
		for _, x := range sc.Tags {
			if x == tag {
				return true
			}
		}
		return false
	}
	for _, sc := range loadCorpus(t) {
		var hostile, benignAnnotated, expectedMiss, expectedFP int
		for _, st := range sc.Steps {
			if st.Hostile == nil {
				continue
			}
			expectsEdge := st.Expect != nil && st.Expect.Edge != nil
			if *st.Hostile {
				hostile++
				if expectsEdge && !*st.Expect.Edge {
					expectedMiss++
				}
			} else {
				benignAnnotated++
				if expectsEdge && *st.Expect.Edge {
					expectedFP++
				}
			}
		}
		switch {
		case has(sc, "attack") && hostile == 0:
			t.Errorf("%s: tagged attack but marks no step hostile", sc.Name)
		case has(sc, "benign") && hostile > 0:
			t.Errorf("%s: tagged benign but marks %d step(s) hostile", sc.Name, hostile)
		}
		if has(sc, "known-miss") && expectedMiss == 0 {
			t.Errorf("%s: tagged known-miss but records no hostile step with expect.edge=false", sc.Name)
		}
		if has(sc, "known-fp") && expectedFP == 0 {
			t.Errorf("%s: tagged known-fp but records no benign step with expect.edge=true", sc.Name)
		}
		if (has(sc, "known-miss") || has(sc, "known-fp")) && !hasNote(sc) {
			t.Errorf("%s: a known miss or false positive must say why in a note", sc.Name)
		}
	}
}

func hasNote(sc *Scenario) bool {
	for _, st := range sc.Steps {
		if st.Note != "" {
			return true
		}
	}
	return false
}
