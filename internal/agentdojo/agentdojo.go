package agentdojo

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

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

type Message struct {
	Role       string         `json:"role"`
	Content    Content        `json:"content"`
	ToolCalls  []FunctionCall `json:"tool_calls"`
	ToolCall   *FunctionCall  `json:"tool_call"`
	ToolCallID *string        `json:"tool_call_id"`
	Error      *string        `json:"error"`
}

type FunctionCall struct {
	Function string         `json:"function"`
	Args     map[string]any `json:"args"`
	ID       *string        `json:"id"`
}

type Content struct {
	Text string
}

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

var dosAttacks = map[string]bool{
	"dos": true, "swearwords_dos": true, "captcha_dos": true,
	"offensive_email_dos": true, "felony_dos": true,
}

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

func (r *Run) Classify() Outcome {
	if r.InjectionTaskID == nil || *r.InjectionTaskID == "" {

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

func (r *Run) Name() string {
	return strings.Join([]string{
		clean(r.PipelineName), clean(r.SuiteName), clean(r.UserTaskID),
		clean(deref(r.AttackType)), clean(deref(r.InjectionTaskID)),
	}, "__")
}

func (r *Run) Server() string {
	return "agentdojo-" + strings.ToLower(clean(r.SuiteName))
}

const cwd = "/home/dev/agentdojo"

type payload struct {
	HookEventName string `json:"hook_event_name"`
	SessionID     string `json:"session_id"`
	PromptID      string `json:"prompt_id,omitempty"`
	CWD           string `json:"cwd"`
	UserInput     string `json:"user_input,omitempty"`
	ToolName      string `json:"tool_name,omitempty"`
	ToolUseID     string `json:"tool_use_id,omitempty"`

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

	var pending []string

	steps := 0
	for i, m := range r.Messages {
		switch m.Role {
		case "system":

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
