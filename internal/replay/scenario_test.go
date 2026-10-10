package replay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, src string) *Scenario {
	t.Helper()
	sc, err := Parse(strings.NewReader(src), "t.jsonl")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return sc
}

func TestParseHeaderBareAndWrappedSteps(t *testing.T) {
	sc := parse(t, `# a comment, and a blank line below

{"scenario":{"name":"demo","description":"d","tags":["x"],"config":{"trusted_content_domains":["example.com"]}}}
{"hook_event_name":"SessionStart","session_id":"s1"}
{"payload":{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}},"hostile":true,"note":"n","expect":{"edge":false}}
`)
	if sc.Name != "demo" || sc.Description != "d" || len(sc.Tags) != 1 {
		t.Errorf("header = %+v", sc.Header)
	}
	if sc.Config == nil || len(sc.Config.TrustedContentDomains) != 1 {
		t.Errorf("config overrides not parsed: %+v", sc.Config)
	}
	if len(sc.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(sc.Steps))
	}
	if sc.Steps[0].N != 1 || sc.Steps[1].N != 2 {
		t.Errorf("step numbers = %d, %d; want 1, 2 (steps, not lines)", sc.Steps[0].N, sc.Steps[1].N)
	}

	if sc.Steps[0].Line != 4 || sc.Steps[1].Line != 5 {
		t.Errorf("lines = %d, %d; want 4, 5", sc.Steps[0].Line, sc.Steps[1].Line)
	}
	st := sc.Steps[1]
	if st.Hostile == nil || !*st.Hostile || st.Note != "n" || st.Expect == nil || *st.Expect.Edge {
		t.Errorf("wrapped step = %+v", st)
	}
	if st.Payload.Command() != "ls" {
		t.Errorf("payload not decoded: %+v", st.Payload)
	}
}

func TestParseDefaultsTheNameFromTheFile(t *testing.T) {
	sc, err := Parse(strings.NewReader(`{"hook_event_name":"SessionStart","session_id":"s"}`+"\n"), "dir/my-scenario.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if sc.Name != "my-scenario" {
		t.Errorf("name = %q, want my-scenario", sc.Name)
	}
}

func TestParseRejectsWhatWouldSilentlyAssertNothing(t *testing.T) {
	const ok = `{"hook_event_name":"SessionStart","session_id":"s"}`
	pre := `{"hook_event_name":"PreToolUse","session_id":"s"}`
	cases := []struct {
		name, src, want string
	}{
		{"unknown expect key", `{"payload":` + pre + `,"expect":{"egde":true}}`, "egde"},
		{"unknown step key", `{"payload":` + pre + `,"hostil":true}`, "hostil"},
		{"unknown header key", `{"scenario":{"name":"x","tag":["a"]}}` + "\n" + ok, "tag"},
		{"unknown config key", `{"scenario":{"config":{"trusted_domains":["a"]}}}` + "\n" + ok, "trusted_domains"},
		{"extra key on the header line", `{"scenario":{"name":"x"},"payload":` + pre + `}` + "\n" + ok, "header"},
		{"second header", `{"scenario":{"name":"a"}}` + "\n" + `{"scenario":{"name":"b"}}` + "\n" + ok, "second header"},
		{"header after a step", ok + "\n" + `{"scenario":{"name":"a"}}`, "before the first step"},
		{"no session id", `{"hook_event_name":"SessionStart"}`, "session_id"},
		{"no hook name", `{"payload":{"session_id":"s"}}`, "hook_event_name"},
		{"hostile on a non-PreToolUse", `{"payload":{"hook_event_name":"PostToolUse","session_id":"s"},"hostile":true}`, "PreToolUse"},
		{"edge_from forward", `{"payload":` + pre + `,"expect":{"edge_from":1}}`, "earlier step"},
		{"edge_from negative", ok + "\n" + `{"payload":` + pre + `,"expect":{"edge_from":-1}}`, "1-based"},
		{"not JSON", `this is not json`, "JSON"},
		{"matches no line kind", `{"something":"else"}`, "neither"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.src+"\n"), "t.jsonl")
			if err == nil {
				t.Fatalf("accepted %q", c.src)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
			if !strings.Contains(err.Error(), "t.jsonl:") {
				t.Errorf("error %q carries no file:line", err)
			}
		})
	}
}

func TestParseToleratesUnknownPayloadFields(t *testing.T) {
	parse(t, `{"hook_event_name":"SessionStart","session_id":"s","a_field_from_a_newer_claude_code":1}`+"\n")
	parse(t, `{"payload":{"hook_event_name":"SessionStart","session_id":"s","newer":{"x":1}}}`+"\n")
}

func TestParseRefusesAnEmptyScenario(t *testing.T) {
	if _, err := Parse(strings.NewReader("# only a comment\n"), "t.jsonl"); err == nil {
		t.Error("an empty scenario would pass every check; it must be an error")
	}
}

func TestParseHandlesAFinalLineWithoutNewline(t *testing.T) {
	sc, err := Parse(strings.NewReader(`{"hook_event_name":"SessionStart","session_id":"s"}`), "t.jsonl")
	if err != nil || len(sc.Steps) != 1 {
		t.Errorf("steps=%v err=%v", sc, err)
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const oneStep = `{"hook_event_name":"SessionStart","session_id":"s"}` + "\n"

func TestLoadReadsADirectoryInNameOrder(t *testing.T) {
	d := t.TempDir()
	writeFile(t, d, "b.jsonl", oneStep)
	writeFile(t, d, "a.jsonl", oneStep)
	writeFile(t, d, "notes.txt", "ignored")
	if err := os.Mkdir(filepath.Join(d, "sub.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("loaded %v, want [a b] in order (a run must be reproducible)", names(got))
	}
}

func TestLoadAcceptsFilesAndDirectoriesTogether(t *testing.T) {
	d := t.TempDir()
	f := writeFile(t, d, "x.jsonl", oneStep)
	d2 := t.TempDir()
	writeFile(t, d2, "y.jsonl", oneStep)
	got, err := Load(f, d2)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v", names(got), err)
	}
}

func TestLoadRefusesDuplicateNames(t *testing.T) {
	d := t.TempDir()
	hdr := `{"scenario":{"name":"same"}}` + "\n" + oneStep
	writeFile(t, d, "a.jsonl", hdr)
	writeFile(t, d, "b.jsonl", hdr)
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "same") {
		t.Errorf("err = %v; two files claiming one name make a failure ambiguous", err)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("an empty directory must be an error, not a vacuous pass")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Error("a missing path must be an error")
	}
	d := t.TempDir()
	writeFile(t, d, "bad.jsonl", "not json\n")
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "bad.jsonl") {
		t.Errorf("err = %v, want it to name the bad file", err)
	}
}

func names(s []*Scenario) []string {
	var out []string
	for _, x := range s {
		out = append(out, x.Name)
	}
	return out
}

func TestParseRunLevelHeader(t *testing.T) {
	sc := parse(t, `{"scenario":{"name":"x","hostile":true,"steps_unlabeled":true}}`+"\n"+oneStep)
	if sc.Hostile == nil || !*sc.Hostile || !sc.StepsUnlabeled {
		t.Errorf("header = %+v", sc.Header)
	}
}

func TestParseRejectsALabeledStepInAnUnlabeledScenario(t *testing.T) {
	src := `{"scenario":{"steps_unlabeled":true}}` + "\n" +
		`{"payload":{"hook_event_name":"PreToolUse","session_id":"s"},"hostile":true}` + "\n"
	if _, err := Parse(strings.NewReader(src), "t.jsonl"); err == nil || !strings.Contains(err.Error(), "steps_unlabeled") {
		t.Errorf("err = %v; a header that says no step is labeled contradicts a labeled step", err)
	}
}
