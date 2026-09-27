// Package hook receives Claude Code hook events over HTTP and turns them into
// normalized events.
//
// Claude Code's `type: "http"` hook POSTs the event JSON to a URL and reads the
// decision from the response body in the same format as a command hook. Pointed
// at 127.0.0.1 this gives ambitd a synchronous decision point with no process
// spawn per event. See docs/02-architecture.md.
package hook

// EventName values are Claude Code's hook event names. Only the ones ambitd
// subscribes to in M0 are listed; the full set is 33 events.
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

// Payload is the inbound hook event. Fields are the union of the common fields
// and the per-event ones ambitd uses; unknown fields are ignored so a Claude
// Code version that adds fields does not break parsing.
//
// tool_input and tool_result are held as raw JSON rather than typed: their shape
// is per-tool, and ambitd only needs to digest them, extract features, and pull
// specific keys such as command or file_path.
type Payload struct {
	// Common fields.
	SessionID      string `json:"session_id"`
	PromptID       string `json:"prompt_id"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	ScratchpadDir  string `json:"scratchpad_dir"`
	PermissionMode string `json:"permission_mode"`
	HookEventName  string `json:"hook_event_name"`
	AgentID        string `json:"agent_id"`
	AgentType      string `json:"agent_type"`

	// SessionStart.
	Model string `json:"model"`

	// UserPromptSubmit.
	UserInput string `json:"user_input"`

	// Tool events.
	ToolName  string         `json:"tool_name"`
	ToolUseID string         `json:"tool_use_id"`
	ToolInput map[string]any `json:"tool_input"`
	// ToolResult is any because a tool result may be a string, an object, or an
	// array depending on the tool.
	ToolResult any    `json:"tool_result"`
	ToolError  string `json:"tool_error"`

	// InstructionsLoaded, FileChanged.
	FilePath   string `json:"file_path"`
	LoadReason string `json:"load_reason"`
	ChangeType string `json:"change_type"`

	// ConfigChange.
	ConfigSource string `json:"config_source"`

	// Compaction.
	CompactionReason string `json:"compaction_reason"`

	// SubagentStop.
	LastAssistantMessage string `json:"last_assistant_message"`

	// SessionEnd.
	EndReason string `json:"end_reason"`
}

// Response is what ambitd returns to Claude Code.
//
// In M0 this is always the zero value, serialized as `{}`: ambitd is
// observe-only and must not change how any session behaves. The fields exist so
// M2's shadow mode and M3's enforcement have somewhere to land, and so the
// shape is reviewable now rather than invented under time pressure later.
type Response struct {
	// HookSpecificOutput carries the decision. Claude Code reads
	// permissionDecision from PreToolUse and decision from PermissionRequest.
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	// SystemMessage is shown to the user or the model depending on the event.
	SystemMessage string `json:"systemMessage,omitempty"`
	// AdditionalContext is appended to the assistant's context on the events
	// that support it.
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName string `json:"hookEventName"`
	// PermissionDecision is allow, deny or block, for PreToolUse.
	PermissionDecision string `json:"permissionDecision,omitempty"`
	// PermissionDecisionReason must always accompany a non-allow decision: a
	// block with no specific reason is a block a developer works around.
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	// Decision is allow, deny or block, for PermissionRequest, which uses a
	// different field name than PreToolUse.
	Decision       string `json:"decision,omitempty"`
	DecisionReason string `json:"decisionReason,omitempty"`
}

// StringField pulls a string from tool_input, which is shaped per tool.
func (p *Payload) StringField(key string) string {
	if p.ToolInput == nil {
		return ""
	}
	if v, ok := p.ToolInput[key].(string); ok {
		return v
	}
	return ""
}

// Command returns the shell command for a Bash-family tool call.
func (p *Payload) Command() string { return p.StringField("command") }

// Paths returns the filesystem paths a tool call references.
//
// Tool input keys vary by tool: Read and Write use file_path, Glob and Grep use
// path, Edit uses file_path, and NotebookEdit uses notebook_path. Anything not
// listed here is simply not path-classified, which means a zone label is absent
// rather than wrong.
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
	// Multi-file tools pass an array.
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

// IsMCPTool reports whether the tool name is an MCP tool, and returns the server
// and tool. Claude Code names MCP tools mcp__<server>__<tool>.
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
	// A server with no tool suffix is still an MCP call.
	return rest, "", true
}
