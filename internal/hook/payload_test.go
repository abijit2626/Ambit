package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A hook payload whose key names differ from the ones Payload reads decodes without any error and
// leaves the field empty: for months every prompt was recorded with no text, because the code read
// "user_input" and Claude Code sends "prompt". The tests here are built from key sets recorded off
// a real Claude Code, so a wrong name fails here instead of in a lab.

const shapesFile = "testdata/claude-code-2.1.278-shapes.txt"

type shapeLine struct {
	event string
	shape string
}

func loadShapes(t *testing.T) []shapeLine {
	t.Helper()
	raw, err := os.ReadFile(shapesFile)
	if err != nil {
		t.Fatalf("read %s: %v", shapesFile, err)
	}
	var out []shapeLine
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ev, shape, ok := strings.Cut(line, " => ")
		if !ok {
			t.Fatalf("%s: line %q is not 'Event => shape'", shapesFile, line)
		}
		out = append(out, shapeLine{ev, shape})
	}
	if len(out) < 10 {
		t.Fatalf("%s has only %d shapes", shapesFile, len(out))
	}
	return out
}

// shapeJSON turns a recorded shape into a JSON document with a placeholder of the right type for
// every key. Only names and types were recorded, so the values are made up.
func shapeJSON(t *testing.T, shape string) string {
	t.Helper()
	pos := 0
	var parse func() string
	parse = func() string {
		start := pos
		for pos < len(shape) && (shape[pos] >= 'a' && shape[pos] <= 'z') {
			pos++
		}
		word := shape[start:pos]
		switch word {
		case "string":
			return `"placeholder"`
		case "number":
			return `1`
		case "bool":
			return `true`
		case "null":
			return `null`
		case "array":
			return `[]`
		case "object":
			if pos < len(shape) && shape[pos] == '{' {
				pos++
				var parts []string
				for shape[pos] != '}' {
					ks := pos
					for shape[pos] != ':' {
						pos++
					}
					key := shape[ks:pos]
					pos++
					parts = append(parts, fmt.Sprintf("%q:%s", key, parse()))
					if shape[pos] == ',' {
						pos++
					}
				}
				pos++
				return "{" + strings.Join(parts, ",") + "}"
			}
			return `{}`
		}
		t.Fatalf("shape %q: unknown type %q at %d", shape, word, start)
		return ""
	}
	out := parse()
	if pos != len(shape) {
		t.Fatalf("shape %q: trailing text at %d", shape, pos)
	}
	return out
}

func decodeShape(t *testing.T, s shapeLine) Payload {
	t.Helper()
	var p Payload
	if err := json.Unmarshal([]byte(shapeJSON(t, s.shape)), &p); err != nil {
		t.Fatalf("%s shape does not decode into Payload: %v", s.event, err)
	}
	return p
}

func TestEveryRecordedShapeDecodes(t *testing.T) {
	for _, s := range loadShapes(t) {
		p := decodeShape(t, s)
		if p.HookEventName != "placeholder" {
			t.Errorf("%s: hook_event_name did not decode (%q)", s.event, p.HookEventName)
		}
		if p.SessionID == "" {
			t.Errorf("%s: session_id did not decode", s.event)
		}
	}
}

func TestPayloadReadsTheFieldsClaudeCodeSendsForEachEvent(t *testing.T) {
	type check struct {
		what string
		ok   func(p *Payload) bool
	}
	nonEmpty := func(what string, get func(p *Payload) string) check {
		return check{what, func(p *Payload) bool { return get(p) != "" }}
	}
	checks := map[string][]check{
		"SessionStart": {
			nonEmpty("model", func(p *Payload) string { return p.Model }),
			nonEmpty("cwd", func(p *Payload) string { return p.CWD }),
			{"no permission_mode: Claude Code does not send one at session start", func(p *Payload) bool { return p.PermissionMode == "" }},
		},
		"UserPromptSubmit": {
			nonEmpty("prompt text", func(p *Payload) string { return p.PromptText() }),
			nonEmpty("permission_mode", func(p *Payload) string { return p.PermissionMode }),
			nonEmpty("prompt_id", func(p *Payload) string { return p.PromptID }),
		},
		"PreToolUse": {
			nonEmpty("tool_name", func(p *Payload) string { return p.ToolName }),
			nonEmpty("tool_use_id", func(p *Payload) string { return p.ToolUseID }),
			{"tool_input", func(p *Payload) bool { return len(p.ToolInput) > 0 }},
			nonEmpty("permission_mode", func(p *Payload) string { return p.PermissionMode }),
		},
		"PostToolUse": {
			nonEmpty("tool_name", func(p *Payload) string { return p.ToolName }),
			{"tool output (tool_response)", func(p *Payload) bool { _, ok := p.ToolOutput(); return ok }},
			{"tool output text", func(p *Payload) bool { s, _ := p.ToolOutput(); return s != "" }},
		},
		"PostToolUseFailure": {
			nonEmpty("tool failure text (error)", func(p *Payload) string { return p.ToolFailure() }),
			nonEmpty("tool_name", func(p *Payload) string { return p.ToolName }),
		},
		"InstructionsLoaded": {
			nonEmpty("file_path", func(p *Payload) string { return p.FilePath }),
			nonEmpty("load_reason", func(p *Payload) string { return p.LoadReason }),
		},
		"SubagentStart": {
			nonEmpty("agent_id", func(p *Payload) string { return p.AgentID }),
			nonEmpty("agent_type", func(p *Payload) string { return p.AgentType }),
		},
		"SubagentStop": {
			nonEmpty("agent_id", func(p *Payload) string { return p.AgentID }),
			nonEmpty("agent_type", func(p *Payload) string { return p.AgentType }),
		},
		"PreCompact":  {nonEmpty("trigger", func(p *Payload) string { return p.Trigger })},
		"PostCompact": {nonEmpty("trigger", func(p *Payload) string { return p.Trigger })},
		"SessionEnd":  {nonEmpty("reason", func(p *Payload) string { return p.Reason })},
	}

	covered := map[string]bool{}
	for _, s := range loadShapes(t) {
		want, ok := checks[s.event]
		if !ok {
			t.Errorf("%s has a recorded shape but no check here", s.event)
			continue
		}
		covered[s.event] = true
		p := decodeShape(t, s)
		for _, c := range want {
			// last_assistant_message is the one key a SubagentStop may omit; nothing above needs it
			if !c.ok(&p) {
				t.Errorf("%s: %s is not readable from a payload with exactly the keys Claude Code sent:\n  %s", s.event, c.what, s.shape)
			}
		}
	}
	for ev := range checks {
		if !covered[ev] {
			t.Errorf("no recorded shape for %s, so its checks ran against nothing", ev)
		}
	}
}

// legacyNames are names an earlier version of Payload guessed. Nothing recorded sends them.
var legacyNames = map[string]string{
	"user_input":  "first guess for prompt",
	"tool_result": "first guess for tool_response",
	"tool_error":  "first guess for error",
}

// unverifiedNames are real as far as the hooks reference goes but were not in the recording.
var unverifiedNames = map[string]string{
	"config_source": "ConfigChange was not triggered in the recording",
	"change_type":   "ConfigChange (and FileChanged) were not triggered in the recording",
}

func TestEveryPayloadKeyWasSeenOrIsListedAsLegacyOrUnverified(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range loadShapes(t) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(shapeJSON(t, s.shape)), &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			seen[k] = true
		}
	}

	typ := reflect.TypeOf(Payload{})
	var tags []string
	for i := 0; i < typ.NumField(); i++ {
		tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if tag != "" && tag != "-" {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)

	for _, tag := range tags {
		_, legacy := legacyNames[tag]
		_, unverified := unverifiedNames[tag]
		switch {
		case seen[tag] && (legacy || unverified):
			t.Errorf("%q was seen in the recording; remove it from the legacy/unverified lists", tag)
		case !seen[tag] && !legacy && !unverified:
			t.Errorf("Payload reads the key %q, which no recorded Claude Code payload contains. Either the name is wrong (the way user_input was) or it belongs to an event that was not recorded: record one with a key-name probe and add the shape to %s, or list it in unverifiedNames with the reason", tag, shapesFile)
		}
	}
	for tag := range legacyNames {
		found := false
		for _, g := range tags {
			found = found || g == tag
		}
		if !found {
			t.Errorf("legacyNames lists %q, which Payload no longer reads", tag)
		}
	}
}

func TestRealNamesWinOverLegacyNames(t *testing.T) {
	var p Payload
	raw := `{"prompt":"real","user_input":"old","tool_response":"real out","tool_result":"old out","error":"real err","tool_error":"old err"}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if p.PromptText() != "real" {
		t.Errorf("PromptText = %q", p.PromptText())
	}
	if out, _ := p.ToolOutput(); out != "real out" {
		t.Errorf("ToolOutput = %q", out)
	}
	if p.ToolFailure() != "real err" {
		t.Errorf("ToolFailure = %q", p.ToolFailure())
	}
}

func TestLegacyNamesStillWorkWhenTheRealOnesAreAbsent(t *testing.T) {
	var p Payload
	if err := json.Unmarshal([]byte(`{"user_input":"old","tool_result":"old out","tool_error":"old err"}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.PromptText() != "old" || p.ToolFailure() != "old err" {
		t.Errorf("legacy prompt/failure not read: %q %q", p.PromptText(), p.ToolFailure())
	}
	if out, ok := p.ToolOutput(); !ok || out != "old out" {
		t.Errorf("legacy tool output = %q, %v", out, ok)
	}
}

func TestToolOutputFlattensWhatToolsReturn(t *testing.T) {
	cases := []struct {
		name   string
		json   string
		want   string
		wantOK bool
	}{
		{"absent", `{}`, "", false},
		{"null", `{"tool_response":null}`, "", false},
		{"empty string is still output", `{"tool_response":""}`, "", true},
		{"plain string", `{"tool_response":"page text"}`, "page text", true},
		{"bash object: string leaves in key order, booleans skipped",
			`{"tool_response":{"stdout":"out","interrupted":false,"stderr":"err","isImage":false}}`, "err\nout", true},
		{"nested file content",
			`{"tool_response":{"type":"text","file":{"filePath":"/a/b","content":"body","numLines":3}}}`, "body\n/a/b\ntext", true},
		{"arrays", `{"tool_response":{"content":[{"text":"one"},{"text":"two"}]}}`, "one\ntwo", true},
		{"numbers only", `{"tool_response":{"n":1,"ok":true}}`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p Payload
			if err := json.Unmarshal([]byte(c.json), &p); err != nil {
				t.Fatal(err)
			}
			got, ok := p.ToolOutput()
			if got != c.want || ok != c.wantOK {
				t.Errorf("ToolOutput() = %q, %v; want %q, %v", got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestToolOutputIsBounded(t *testing.T) {
	big := strings.Repeat("a", maxOutputText+5000)
	p := Payload{ToolResponse: map[string]any{"a": big, "b": big}}
	got, _ := p.ToolOutput()
	if len(got) > maxOutputText {
		t.Errorf("flattened output is %d bytes, over the %d limit", len(got), maxOutputText)
	}

	var deep any = "buried"
	for i := 0; i < maxOutputDepth+4; i++ {
		deep = map[string]any{"k": deep}
	}
	p = Payload{ToolResponse: deep}
	if got, _ := p.ToolOutput(); got != "" {
		t.Errorf("a string %d levels down was read: %q", maxOutputDepth+4, got)
	}
}

func TestToolOutputIsDeterministic(t *testing.T) {
	m := map[string]any{}
	for i := 0; i < 20; i++ {
		m[fmt.Sprintf("k%02d", i)] = fmt.Sprintf("v%02d", i)
	}
	p := Payload{ToolResponse: m}
	first, _ := p.ToolOutput()
	for i := 0; i < 20; i++ {
		if again, _ := p.ToolOutput(); again != first {
			t.Fatal("flattened output changed between calls; the fingerprint of a result must not depend on map order")
		}
	}
}
