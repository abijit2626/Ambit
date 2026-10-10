package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abijit2626/ambit/internal/hook"
)

type Header struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Tags        []string         `json:"tags"`
	Config      *ConfigOverrides `json:"config"`

	Hostile *bool `json:"hostile"`

	StepsUnlabeled bool `json:"steps_unlabeled"`
}

type ConfigOverrides struct {
	Home                  string   `json:"home"`
	TrustedRepoPaths      []string `json:"trusted_repo_paths"`
	TrustedMCPServers     []string `json:"trusted_mcp_servers"`
	TrustedContentDomains []string `json:"trusted_content_domains"`
	ExtraUntrustedPaths   []string `json:"extra_untrusted_paths"`

	MCPToolLabels map[string]map[string][]string `json:"mcp_tool_labels"`
}

type Expect struct {
	Edge *bool `json:"edge"`

	EdgeClass string `json:"edge_class"`

	EdgeFrom int `json:"edge_from"`

	Crosses *bool `json:"crosses"`

	R2 *string `json:"r2"`

	Taint string `json:"taint"`

	Decision string `json:"decision"`
	Rule     string `json:"rule"`

	TurnDecision string `json:"turn_decision"`

	Exfil      *bool  `json:"exfil"`
	ExfilClass string `json:"exfil_class"`
}

type Step struct {
	N int

	Line    int
	Payload hook.Payload

	Hostile *bool
	Expect  *Expect
	Note    string
}

type Scenario struct {
	Header

	Path  string
	Steps []Step
}

type wrapped struct {
	Payload json.RawMessage `json:"payload"`
	Hostile *bool           `json:"hostile"`
	Expect  *Expect         `json:"expect"`
	Note    string          `json:"note"`
}

type headerLine struct {
	Scenario Header `json:"scenario"`
}

func Parse(r io.Reader, name string) (*Scenario, error) {
	sc := &Scenario{Path: name}
	sc.Name = strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))

	rd := bufio.NewReaderSize(r, 1<<20)
	lineNo := 0
	headerSeen, stepSeen := false, false
	for {
		raw, err := rd.ReadBytes('\n')
		if len(raw) > 0 {
			lineNo++
			if perr := sc.parseLine(raw, lineNo, &headerSeen, &stepSeen); perr != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, lineNo, perr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: read: %w", name, err)
		}
	}
	if len(sc.Steps) == 0 {
		return nil, fmt.Errorf("%s: no steps; a scenario with nothing in it would pass every check", name)
	}
	if sc.StepsUnlabeled {
		for _, st := range sc.Steps {
			if st.Hostile != nil {
				return nil, fmt.Errorf("%s:%d: the header says steps_unlabeled, but this step is labeled hostile=%v", name, st.Line, *st.Hostile)
			}
		}
	}
	return sc, nil
}

func (sc *Scenario) parseLine(raw []byte, lineNo int, headerSeen, stepSeen *bool) error {
	line := bytes.TrimSpace(raw)
	if len(line) == 0 || line[0] == '#' {
		return nil
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal(line, &keys); err != nil {
		return fmt.Errorf("not a JSON object: %w", err)
	}

	switch {
	case has(keys, "scenario"):
		if *headerSeen {
			return fmt.Errorf("a second header; one scenario per file")
		}
		if *stepSeen {
			return fmt.Errorf("the header must come before the first step")
		}
		if len(keys) != 1 {
			return fmt.Errorf("a header line holds only the \"scenario\" key")
		}
		var h headerLine
		if err := strictDecode(line, &h); err != nil {
			return fmt.Errorf("header: %w", err)
		}
		if h.Scenario.Name == "" {
			h.Scenario.Name = sc.Name
		}
		sc.Header = h.Scenario
		*headerSeen = true
		return nil

	case has(keys, "payload"):
		var w wrapped
		if err := strictDecode(line, &w); err != nil {
			return fmt.Errorf("step: %w", err)
		}
		var p hook.Payload
		if err := json.Unmarshal(w.Payload, &p); err != nil {
			return fmt.Errorf("payload: %w", err)
		}
		return sc.addStep(p, w.Hostile, w.Expect, w.Note, lineNo, stepSeen)

	case has(keys, "hook_event_name"):
		var p hook.Payload
		if err := json.Unmarshal(line, &p); err != nil {
			return fmt.Errorf("payload: %w", err)
		}
		return sc.addStep(p, nil, nil, "", lineNo, stepSeen)
	}
	return fmt.Errorf("neither a header (\"scenario\"), a wrapped step (\"payload\") nor a bare payload (\"hook_event_name\")")
}

func (sc *Scenario) addStep(p hook.Payload, hostile *bool, ex *Expect, note string, lineNo int, stepSeen *bool) error {
	if p.HookEventName == "" {
		return fmt.Errorf("payload has no hook_event_name")
	}
	if p.SessionID == "" {

		return fmt.Errorf("payload has no session_id")
	}
	if hostile != nil && p.HookEventName != hook.EvPreToolUse {
		return fmt.Errorf("\"hostile\" is ground truth for an action, so it belongs on a PreToolUse, not %s", p.HookEventName)
	}
	if ex != nil && ex.EdgeFrom < 0 {
		return fmt.Errorf("expect.edge_from is a 1-based step number")
	}
	*stepSeen = true
	sc.Steps = append(sc.Steps, Step{
		N: len(sc.Steps) + 1, Line: lineNo,
		Payload: p, Hostile: hostile, Expect: ex, Note: note,
	})

	if ex != nil && ex.EdgeFrom >= len(sc.Steps) {
		return fmt.Errorf("expect.edge_from %d does not name an earlier step (this is step %d)", ex.EdgeFrom, len(sc.Steps))
	}
	return nil
}

func has(m map[string]json.RawMessage, k string) bool { _, ok := m[k]; return ok }

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func Load(paths ...string) ([]*Scenario, error) {
	var files []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			files = append(files, p)
			continue
		}
		ents, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		var in []string
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				in = append(in, filepath.Join(p, e.Name()))
			}
		}
		sort.Strings(in)
		files = append(files, in...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no scenarios found in %s", strings.Join(paths, ", "))
	}

	seen := map[string]string{}
	var out []*Scenario
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc, err := Parse(fh, f)
		fh.Close()
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[sc.Name]; dup {
			return nil, fmt.Errorf("scenario name %q is used by both %s and %s", sc.Name, prev, f)
		}
		seen[sc.Name] = f
		out = append(out, sc)
	}
	return out, nil
}
