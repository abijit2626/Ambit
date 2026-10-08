// Package agentdojo converts AgentDojo run logs into ambit replay trajectories.
//
// AgentDojo (Debenedetti et al., ETH Zurich; MIT licensed) runs a tool-using agent
// through a suite of user tasks, optionally with a prompt injection planted in a tool's
// data, and saves each run as one JSON file:
//
//	runs/<pipeline>/<suite>/<user_task>/<attack_type|none>/<injection_task|none>.json
//
// holding the chat (system, user, assistant with tool calls, tool results) and AgentDojo's
// own verdicts: "utility" (the user's task was done) and "security" (the injection task
// was done, i.e. the attack succeeded). The upstream repository publishes tens of
// thousands of these for real models, which makes it the first corpus ambit can be
// measured against that was not written by the engine's author.
//
// # Mapping
//
// Each suite becomes one MCP server, "agentdojo-<suite>", that the operator has not
// classified, so a function call becomes a PreToolUse for mcp__agentdojo-<suite>__<fn>
// and its result a PostToolUse (PostToolUseFailure when the tool raised). That is how
// such a toolset would actually reach Claude Code, and it routes every result through
// the same untrusted-ingest path a deployment would: an unclassified server sets
// Rule-of-Two bits A and C on every call. A user message becomes UserPromptSubmit, so
// what the user asked for is declared to the provenance engine. System messages and the
// assistant's prose have no hook and are dropped.
//
// # Ground truth
//
// AgentDojo labels runs, not calls, and the adapter takes only what it can stand behind:
//
//   - An injected run whose attack succeeded ("security": true, no error, not a DoS
//     attack) is hostile.
//   - A run with no injection is benign, and so is every call in it. That includes the
//     runs AgentDojo makes with an injection task's goal as the USER's request: the user
//     asked for those actions, so flagging them would be a false positive.
//   - Every other injected run is left without a run label, because its outcome is
//     ambiguous: a failed attack may still have taken a hostile step that AgentDojo's
//     checker did not count; AgentDojo writes "security": true on an API error or a
//     context overflow, which is not an attack succeeding; and for DoS attacks it sets
//     security to "not utility", which means something else entirely.
//
// Injected runs are marked steps_unlabeled, because AgentDojo says nothing about WHICH
// call was the attacker's. The only per-call label derivable from the log is "this
// call's arguments contain text from the injection", and that is the very signal the
// provenance engine computes, so using it would grade the engine against itself.
//
// "security" is never read on a run with no injection. AgentDojo writes true there, and
// it does not mean anything.
package agentdojo

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Run is one AgentDojo run log. Pointers distinguish an absent or null field from a zero
// value, because "security": null and "security": false mean different things here.
type Run struct {
	SuiteName       string            `json:"suite_name"`
	PipelineName    string            `json:"pipeline_name"`
	UserTaskID      string            `json:"user_task_id"`
	InjectionTaskID *string           `json:"injection_task_id"`
	AttackType      *string           `json:"attack_type"`
	Injections      map[string]string `json:"injections"`
	Messages        []Message         `json:"messages"`
	Error           *string           `json:"error"`
	Utility         *bool             `json:"utility"`
	Security        *bool             `json:"security"`
}

// Message is one chat message. Content is normalized to text by its unmarshaller.
type Message struct {
	Role       string         `json:"role"`
	Content    Content        `json:"content"`
	ToolCalls  []FunctionCall `json:"tool_calls"`
	ToolCall   *FunctionCall  `json:"tool_call"`
	ToolCallID *string        `json:"tool_call_id"`
	Error      *string        `json:"error"`
}

// FunctionCall is a tool call the agent requested.
type FunctionCall struct {
	Function string         `json:"function"`
	Args     map[string]any `json:"args"`
	ID       *string        `json:"id"`
}

// Content is a message body. AgentDojo has stored it two ways: the published run logs
// carry a plain string, and current versions a list of typed blocks
// ({"type": "text" | "thinking" | "redacted_thinking", "content": ...}). Only text blocks
// are kept. Thinking is the model's reasoning, which ambit does not monitor and which
// no hook would carry.
type Content struct {
	Text string
}

// UnmarshalJSON accepts a string, a list of blocks, or null.
func (c *Content) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		c.Text = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		c.Text = s
		return nil
	}
	var blocks []struct {
		Type    string  `json:"type"`
		Content *string `json:"content"`
	}
	if err := json.Unmarshal(b, &blocks); err != nil {
		return fmt.Errorf("content is neither a string nor a list of blocks: %w", err)
	}
	var parts []string
	for _, bl := range blocks {
		if bl.Type == "text" && bl.Content != nil {
			parts = append(parts, *bl.Content)
		}
	}
	c.Text = strings.Join(parts, "\n")
	return nil
}

// Parse decodes one run log and checks it is one.
func Parse(b []byte) (*Run, error) {
	var r Run
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.SuiteName == "" || r.UserTaskID == "" {
		return nil, fmt.Errorf("not an AgentDojo run log: no suite_name or user_task_id")
	}
	if r.Messages == nil {
		return nil, fmt.Errorf("not an AgentDojo run log: no messages")
	}
	return &r, nil
}

// dosAttacks are AgentDojo's denial-of-service attacks (attacks/dos_attacks.py). For
// these "security" is set to "not utility": the goal is to stop the agent, not to make
// it act, so there is no hostile action for provenance to find and the label means
// something else.
var dosAttacks = map[string]bool{
	"dos": true, "swearwords_dos": true, "captcha_dos": true,
	"offensive_email_dos": true, "felony_dos": true,
}

// Outcome classifies a run for labeling.
type Outcome string

const (
	OutcomeNoAttack        Outcome = "no-attack"
	OutcomeUserGoal        Outcome = "user-requested-goal"
	OutcomeAttackSucceeded Outcome = "attack-succeeded"
	OutcomeAttackFailed    Outcome = "attack-failed"
	OutcomeErrored         Outcome = "errored"
	OutcomeDoS             Outcome = "dos"
	OutcomeUnscored        Outcome = "unscored"
)

// Classify returns the run's outcome. See the package comment for why each case is
// labeled the way it is.
func (r *Run) Classify() Outcome {
	if r.InjectionTaskID == nil || *r.InjectionTaskID == "" {
		// AgentDojo runs each injection task's goal as a plain user task to check it is
		// achievable; those land under user_task_id "injection_task_N".
		if strings.HasPrefix(r.UserTaskID, "injection_task_") {
			return OutcomeUserGoal
		}
		return OutcomeNoAttack
	}
	switch {
	case r.Error != nil && *r.Error != "":
		return OutcomeErrored
	case r.AttackType != nil && dosAttacks[*r.AttackType]:
		return OutcomeDoS
	case r.Security == nil:
		return OutcomeUnscored
	case *r.Security:
		return OutcomeAttackSucceeded
	}
	return OutcomeAttackFailed
}

// Hostile returns the run-level label, or nil when the run should carry none.
func (o Outcome) Hostile() *bool {
	t, f := true, false
	switch o {
	case OutcomeAttackSucceeded:
		return &t
	case OutcomeNoAttack, OutcomeUserGoal:
		return &f
	}
	return nil
}

// Injected reports whether the run had an injection planted, which is what makes its
// calls unlabeled.
func (o Outcome) Injected() bool {
	return o != OutcomeNoAttack && o != OutcomeUserGoal
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func clean(s string) string {
	s = unsafeName.ReplaceAllString(s, "_")
	if s == "" {
		return "none"
	}
	return s
}

func deref(p *string) string {
	if p == nil || *p == "" {
		return "none"
	}
	return *p
}

// Name is a file-safe scenario name, unique per run log within one runs tree.
func (r *Run) Name() string {
	return strings.Join([]string{
		clean(r.PipelineName), clean(r.SuiteName), clean(r.UserTaskID),
		clean(deref(r.AttackType)), clean(deref(r.InjectionTaskID)),
	}, "__")
}

// Server is the MCP server name a suite's tools appear under.
func (r *Run) Server() string {
	return "agentdojo-" + strings.ToLower(clean(r.SuiteName))
}

// cwd is a fixed working directory. AgentDojo environments have no filesystem the agent
// works in, so any value is synthetic; a fixed one keeps zone classification stable.
const cwd = "/home/dev/agentdojo"

// payload is the subset of a Claude Code hook payload the adapter writes. Field names
// match internal/hook.Payload's JSON tags.
type payload struct {
	HookEventName string `json:"hook_event_name"`
	SessionID     string `json:"session_id"`
	PromptID      string `json:"prompt_id,omitempty"`
	CWD           string `json:"cwd"`
	UserInput     string `json:"user_input,omitempty"`
	ToolName      string `json:"tool_name,omitempty"`
	ToolUseID     string `json:"tool_use_id,omitempty"`
	// ToolInput is a pointer so that a call with no arguments still renders "tool_input": {}
	// (Claude Code always sends the field on tool events), while a prompt omits it.
	ToolInput  *map[string]any `json:"tool_input,omitempty"`
	ToolResult *string         `json:"tool_result,omitempty"`
	ToolError  string          `json:"tool_error,omitempty"`
}

type header struct {
	Scenario struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
		Hostile        *bool    `json:"hostile,omitempty"`
		StepsUnlabeled bool     `json:"steps_unlabeled,omitempty"`
	} `json:"scenario"`
}

// Convert renders a run as a replay trajectory: JSON lines, a header then one hook
// payload per line. It returns the outcome so a caller can report what it converted.
func Convert(r *Run) ([]byte, Outcome, error) {
	out := r.Classify()

	var h header
	h.Scenario.Name = r.Name()
	h.Scenario.Description = fmt.Sprintf("AgentDojo %s / %s, pipeline %s, attack %s, injection task %s: %s",
		r.SuiteName, r.UserTaskID, r.PipelineName, deref(r.AttackType), deref(r.InjectionTaskID), out)
	h.Scenario.Tags = []string{"agentdojo", r.SuiteName, string(out)}
	if r.AttackType != nil && *r.AttackType != "" {
		h.Scenario.Tags = append(h.Scenario.Tags, "attack:"+*r.AttackType)
	}
	h.Scenario.Hostile = out.Hostile()
	h.Scenario.StepsUnlabeled = out.Injected()

	var b strings.Builder
	if err := writeLine(&b, h); err != nil {
		return nil, out, err
	}

	session := "agentdojo:" + r.Name()
	server := r.Server()
	prompts, synth := 0, 0
	// pending holds the ids of calls not yet answered, in order, so a tool result that carries
	// no id of its own pairs with the call it answers.
	var pending []string

	steps := 0
	for i, m := range r.Messages {
		switch m.Role {
		case "system":
			// No hook carries the system prompt.
		case "user":
			prompts++
			steps++
			if err := writeLine(&b, payload{
				HookEventName: "UserPromptSubmit", SessionID: session, CWD: cwd,
				PromptID: fmt.Sprintf("p%d", prompts), UserInput: m.Content.Text,
			}); err != nil {
				return nil, out, err
			}
		case "assistant":
			for _, call := range m.ToolCalls {
				if call.Function == "" {
					return nil, out, fmt.Errorf("message %d: a tool call with no function name", i)
				}
				id := ""
				if call.ID != nil && *call.ID != "" {
					id = *call.ID
				} else {
					synth++
					id = fmt.Sprintf("call-%d", synth)
				}
				pending = append(pending, id)
				steps++
				if err := writeLine(&b, payload{
					HookEventName: "PreToolUse", SessionID: session, CWD: cwd,
					PromptID:  fmt.Sprintf("p%d", prompts),
					ToolName:  "mcp__" + server + "__" + call.Function,
					ToolUseID: id, ToolInput: args(call.Args),
				}); err != nil {
					return nil, out, err
				}
			}
		case "tool":
			if m.ToolCall == nil || m.ToolCall.Function == "" {
				return nil, out, fmt.Errorf("message %d: a tool result with no tool_call", i)
			}
			id := ""
			switch {
			case m.ToolCallID != nil && *m.ToolCallID != "":
				id = *m.ToolCallID
			case m.ToolCall.ID != nil && *m.ToolCall.ID != "":
				id = *m.ToolCall.ID
			case len(pending) > 0:
				id = pending[0]
			default:
				synth++
				id = fmt.Sprintf("call-%d", synth)
			}
			pending = remove(pending, id)
			p := payload{
				SessionID: session, CWD: cwd, PromptID: fmt.Sprintf("p%d", prompts),
				ToolName:  "mcp__" + server + "__" + m.ToolCall.Function,
				ToolUseID: id, ToolInput: args(m.ToolCall.Args),
			}
			if m.Error != nil && *m.Error != "" {
				p.HookEventName = "PostToolUseFailure"
				p.ToolError = *m.Error
			} else {
				p.HookEventName = "PostToolUse"
				text := m.Content.Text
				p.ToolResult = &text
			}
			steps++
			if err := writeLine(&b, p); err != nil {
				return nil, out, err
			}
		default:
			return nil, out, fmt.Errorf("message %d: unknown role %q", i, m.Role)
		}
	}
	if steps == 0 {
		return nil, out, fmt.Errorf("the run has no user message and no tool call, so there is nothing to replay")
	}
	return []byte(b.String()), out, nil
}

// args never returns nil: a call with no arguments renders "tool_input": {}, as Claude
// Code sends it, rather than dropping the field.
func args(a map[string]any) *map[string]any {
	if a == nil {
		a = map[string]any{}
	}
	return &a
}

func remove(ids []string, id string) []string {
	for i, x := range ids {
		if x == id {
			return append(ids[:i:i], ids[i+1:]...)
		}
	}
	return ids
}

func writeLine(b *strings.Builder, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.Write(raw)
	b.WriteByte('\n')
	return nil
}
