package hook

import (
	"sort"
	"strings"
)

const (
	EvSessionStart       = "SessionStart"
	EvSessionEnd         = "SessionEnd"
	EvUserPromptSubmit   = "UserPromptSubmit"
	EvPreToolUse         = "PreToolUse"
	EvPostToolUse        = "PostToolUse"
	EvPostToolUseFailure = "PostToolUseFailure"
	EvPermissionRequest  = "PermissionRequest"
	EvPermissionDenied   = "PermissionDenied"
	EvInstructionsLoaded = "InstructionsLoaded"
	EvConfigChange       = "ConfigChange"
	EvFileChanged        = "FileChanged"
	EvSubagentStart      = "SubagentStart"
	EvSubagentStop       = "SubagentStop"
	EvPreCompact         = "PreCompact"
	EvPostCompact        = "PostCompact"
)

// Payload is the JSON Claude Code posts to a hook. The key names come from what Claude Code
// v2.1.278 was seen to send (testdata/claude-code-2.1.278-shapes.txt, key names and value types
// recorded on a Windows machine) and from its hooks reference. Fields marked "legacy" are names
// an earlier version of this file guessed; nothing seen sends them, but the replay corpus and
// the fixture scripts still do, so they stay readable. Read the prompt, tool output and tool
// failure through PromptText, ToolOutput and ToolFailure, never through the raw fields.
type Payload struct {
	SessionID      string `json:"session_id"`
	PromptID       string `json:"prompt_id"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	ScratchpadDir  string `json:"scratchpad_dir"`
	PermissionMode string `json:"permission_mode"`
	HookEventName  string `json:"hook_event_name"`
	AgentID        string `json:"agent_id"`
	AgentType      string `json:"agent_type"`

	Model string `json:"model"`

	// Source is why a SessionStart fired: startup, resume, clear or compact.
	Source string `json:"source"`

	Prompt string `json:"prompt"`

	UserInput string `json:"user_input"` // legacy name for Prompt

	ToolName  string         `json:"tool_name"`
	ToolUseID string         `json:"tool_use_id"`
	ToolInput map[string]any `json:"tool_input"`

	ToolResponse any    `json:"tool_response"`
	Error        string `json:"error"`

	ToolResult any    `json:"tool_result"` // legacy name for ToolResponse
	ToolError  string `json:"tool_error"`  // legacy name for Error

	FilePath   string `json:"file_path"`
	LoadReason string `json:"load_reason"`
	ChangeType string `json:"change_type"`

	ConfigSource string `json:"config_source"`

	Trigger string `json:"trigger"`

	LastAssistantMessage string `json:"last_assistant_message"`

	Reason string `json:"reason"`
}

type Response struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`

	SystemMessage string `json:"systemMessage,omitempty"`

	AdditionalContext string `json:"additionalContext,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName string `json:"hookEventName"`

	PermissionDecision string `json:"permissionDecision,omitempty"`

	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`

	Decision       string `json:"decision,omitempty"`
	DecisionReason string `json:"decisionReason,omitempty"`
}

// PromptText is the text the user submitted. Claude Code sends it as "prompt"; user_input is the
// name this project first assumed.
func (p *Payload) PromptText() string {
	if p.Prompt != "" {
		return p.Prompt
	}
	return p.UserInput
}

// ToolFailure is the error text of a failed tool call ("error", or the legacy "tool_error").
func (p *Payload) ToolFailure() string {
	if p.Error != "" {
		return p.Error
	}
	return p.ToolError
}

// maxOutputText bounds how much of a tool's output is flattened to text, so one huge result
// cannot make a hook handler allocate without limit.
const maxOutputText = 1 << 20

const maxOutputDepth = 8

// ToolOutput is the text of what a tool returned, and whether the payload carried any output
// at all. Claude Code sends "tool_response", which is a string for some tools and an object for
// others (a Bash call has stdout and stderr, a file read nests the content one level down), so
// the string leaves of an object are joined in key order. Numbers and booleans are skipped:
// they carry no content to fingerprint and would only add noise.
func (p *Payload) ToolOutput() (string, bool) {
	v := p.ToolResponse
	if v == nil {
		v = p.ToolResult
	}
	if v == nil {
		return "", false
	}
	var b strings.Builder
	flattenOutput(&b, v, 0)
	return b.String(), true
}

func flattenOutput(b *strings.Builder, v any, depth int) {
	if depth > maxOutputDepth || b.Len() >= maxOutputText {
		return
	}
	switch x := v.(type) {
	case string:
		if b.Len() > 0 && x != "" {
			b.WriteByte('\n')
		}
		room := maxOutputText - b.Len()
		if len(x) > room {
			x = x[:room]
		}
		b.WriteString(x)
	case *string:
		if x != nil {
			flattenOutput(b, *x, depth)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenOutput(b, x[k], depth+1)
		}
	case []any:
		for _, item := range x {
			flattenOutput(b, item, depth+1)
		}
	}
}

func (p *Payload) StringField(key string) string {
	if p.ToolInput == nil {
		return ""
	}
	if v, ok := p.ToolInput[key].(string); ok {
		return v
	}
	return ""
}

func (p *Payload) Command() string { return p.StringField("command") }

func (p *Payload) Paths() []string {
	if p.ToolInput == nil {
		return nil
	}
	var out []string
	for _, key := range []string{"file_path", "path", "notebook_path", "directory"} {
		if v, ok := p.ToolInput[key].(string); ok && v != "" {
			out = append(out, v)
		}
	}

	for _, key := range []string{"file_paths", "paths"} {
		if arr, ok := p.ToolInput[key].([]any); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func IsMCPTool(name string) (server, tool string, ok bool) {
	const prefix = "mcp__"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return "", "", false
	}
	rest := name[len(prefix):]
	for i := 0; i+1 < len(rest); i++ {
		if rest[i] == '_' && rest[i+1] == '_' {
			return rest[:i], rest[i+2:], true
		}
	}

	return rest, "", true
}
