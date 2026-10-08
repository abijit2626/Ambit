package hook

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

	UserInput string `json:"user_input"`

	ToolName  string         `json:"tool_name"`
	ToolUseID string         `json:"tool_use_id"`
	ToolInput map[string]any `json:"tool_input"`

	ToolResult any    `json:"tool_result"`
	ToolError  string `json:"tool_error"`

	FilePath   string `json:"file_path"`
	LoadReason string `json:"load_reason"`
	ChangeType string `json:"change_type"`

	ConfigSource string `json:"config_source"`

	CompactionReason string `json:"compaction_reason"`

	LastAssistantMessage string `json:"last_assistant_message"`

	EndReason string `json:"end_reason"`
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
