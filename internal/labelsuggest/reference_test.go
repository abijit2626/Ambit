package labelsuggest

import (
	"reflect"
	"sort"
	"testing"

	"github.com/abijit2626/ambit/internal/baseline"
	"github.com/abijit2626/ambit/internal/event"
)

// referenceServers are tool names from the reference MCP servers in modelcontextprotocol/servers,
// current and archived, keyed by the name a developer would give each in .mcp.json. They are the
// closest public stand-in for what a cohort runs until its own tool lists are recorded.
var referenceServers = map[string][]string{
	"filesystem": {"read_file", "read_text_file", "read_media_file", "read_multiple_files", "write_file", "edit_file",
		"create_directory", "list_directory", "list_directory_with_sizes", "directory_tree", "move_file",
		"search_files", "get_file_info", "list_allowed_directories"},
	"git": {"git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_commit", "git_add", "git_reset",
		"git_log", "git_create_branch", "git_checkout", "git_show", "git_init", "git_branch"},
	"memory": {"create_entities", "create_relations", "add_observations", "delete_entities", "delete_observations",
		"delete_relations", "read_graph", "search_nodes", "open_nodes"},
	"fetch": {"fetch"},
	"time":  {"get_current_time", "convert_time"},
	"slack": {"slack_list_channels", "slack_post_message", "slack_reply_to_thread", "slack_add_reaction",
		"slack_get_channel_history", "slack_get_thread_replies", "slack_get_users", "slack_get_user_profile"},
	"puppeteer": {"puppeteer_navigate", "puppeteer_screenshot", "puppeteer_click", "puppeteer_fill",
		"puppeteer_select", "puppeteer_hover", "puppeteer_evaluate"},
	"github": {"create_or_update_file", "search_repositories", "create_repository", "get_file_contents", "push_files",
		"create_issue", "create_pull_request", "fork_repository", "create_branch", "list_commits", "list_issues",
		"update_issue", "add_issue_comment", "search_code", "search_issues", "search_users", "get_issue",
		"get_pull_request", "list_pull_requests", "create_pull_request_review", "merge_pull_request",
		"get_pull_request_files", "get_pull_request_status", "update_pull_request_branch",
		"get_pull_request_comments", "get_pull_request_reviews"},
}

func relaxedUnderAnOverclaimingServer(server string, tools []string) []string {
	rec := baseline.ServerRecord{Server: server, Tools: map[string]baseline.ToolRecord{}}
	for _, name := range tools {
		rec.Tools[name] = tool("", event.Annotations{ReadOnlyHint: tp(true)})
	}
	var out []string
	for _, s := range For(rec) {
		if s.Relaxes() {
			out = append(out, s.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// A server that claims readOnlyHint on every tool is the worst case the heuristics face: the hint is
// the server's to write. Under it, only tools whose names read may be suggested read_only. The lists
// below were checked by hand against what each tool does; a change to either is a change in what the
// draft would relax.
func TestReferenceServersUnderAnOverclaimingServer(t *testing.T) {
	want := map[string][]string{
		"filesystem": {"get_file_info", "list_allowed_directories", "list_directory", "list_directory_with_sizes",
			"read_file", "read_media_file", "read_multiple_files", "read_text_file", "search_files"},
		"git":       {"git_show"},
		"memory":    {"read_graph", "search_nodes"},
		"fetch":     nil,
		"time":      {"get_current_time"},
		"slack":     {"slack_get_channel_history", "slack_get_thread_replies", "slack_get_user_profile", "slack_get_users", "slack_list_channels"},
		"puppeteer": nil,
		"github": {"get_file_contents", "get_issue", "get_pull_request", "get_pull_request_comments",
			"get_pull_request_files", "get_pull_request_reviews", "get_pull_request_status", "list_commits",
			"list_issues", "list_pull_requests", "search_code", "search_issues", "search_repositories", "search_users"},
	}
	for server, tools := range referenceServers {
		if got := relaxedUnderAnOverclaimingServer(server, tools); !reflect.DeepEqual(got, want[server]) {
			t.Errorf("%s: read_only suggested for %q, want %q", server, got, want[server])
		}
	}
}

// The server's name in front of a tool's moves the verb, not the rule: slack_get_users reads, and
// slack_post_message still acts.
func TestServerPrefixIsSkipped(t *testing.T) {
	got := byTool(For(baseline.ServerRecord{Server: "slack", Tools: map[string]baseline.ToolRecord{
		"slack_get_users":    tool("", event.Annotations{ReadOnlyHint: tp(true)}),
		"slack_post_message": tool("", event.Annotations{ReadOnlyHint: tp(true)}),
		"slack":              tool("", event.Annotations{ReadOnlyHint: tp(true)}),
	}}))
	if !got["slack_get_users"].Relaxes() {
		t.Errorf("slack_get_users: %v", got["slack_get_users"].Reasons)
	}
	if got["slack_post_message"].Relaxes() || got["slack"].Relaxes() {
		t.Error("the prefix rule relaxed a tool that acts, or one named only for its server")
	}
	other := byTool(For(baseline.ServerRecord{Server: "wiki", Tools: map[string]baseline.ToolRecord{
		"slack_get_users": tool("", event.Annotations{ReadOnlyHint: tp(true)}),
	}}))
	if other["slack_get_users"].Relaxes() {
		t.Error("a prefix that is not this server's name was skipped")
	}
}

func TestReachingAnAddressIsNeverReadOnly(t *testing.T) {
	got := byTool(For(record(map[string]baseline.ToolRecord{
		"fetch":          tool("", event.Annotations{ReadOnlyHint: tp(true)}),
		"get_url":        tool("", event.Annotations{ReadOnlyHint: tp(true)}),
		"read_webhook":   tool("", event.Annotations{ReadOnlyHint: tp(true)}),
		"list_downloads": tool("", event.Annotations{ReadOnlyHint: tp(true)}),
		"get_label":      tool("", event.Annotations{ReadOnlyHint: tp(true)}),
	})))
	for _, name := range []string{"fetch", "get_url", "read_webhook"} {
		if got[name].Relaxes() {
			t.Errorf("%s reaches an address and must not be suggested read_only", name)
		}
	}
	if !got["get_label"].Relaxes() || !got["list_downloads"].Relaxes() {
		t.Error("a reading tool whose name only resembles a reach word was blocked")
	}
}
