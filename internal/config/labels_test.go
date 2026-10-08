package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func labelled() Config {
	c := Default()
	c.MCPToolLabels = map[string]map[string][]string{
		"bank": {
			"get_balance":  {LabelSensitive, LabelReadOnly},
			"get_*":        {LabelReadOnly},
			"read_file":    {LabelUntrusted, LabelReadOnly},
			"send_money":   {},
			"get_history*": {LabelUntrusted},
		},
	}
	return c
}

func TestToolLabelsExactGlobAndUnion(t *testing.T) {
	c := labelled()
	cases := []struct {
		tool string
		want ToolLabels
		ok   bool
	}{
		// Exact entry and the get_* glob both match: their labels union.
		{"get_balance", ToolLabels{Sensitive: true, ReadOnly: true, Names: []string{"read_only", "sensitive"}}, true},
		{"get_iban", ToolLabels{ReadOnly: true, Names: []string{"read_only"}}, true},
		// Two globs match.
		{"get_history_all", ToolLabels{Untrusted: true, ReadOnly: true, Names: []string{"read_only", "untrusted"}}, true},
		{"read_file", ToolLabels{Untrusted: true, ReadOnly: true, Names: []string{"read_only", "untrusted"}}, true},
		// Classified with no labels: acts, carries neither.
		{"send_money", ToolLabels{}, true},
		// Not classified at all: the caller keeps the server-level default.
		{"delete_account", ToolLabels{}, false},
	}
	for _, tc := range cases {
		got, ok := c.ToolLabels("bank", tc.tool)
		if ok != tc.ok || got.Untrusted != tc.want.Untrusted || got.Sensitive != tc.want.Sensitive ||
			got.ReadOnly != tc.want.ReadOnly || !reflect.DeepEqual(got.Names, tc.want.Names) {
			t.Errorf("%s: got %+v ok=%v, want %+v ok=%v", tc.tool, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := c.ToolLabels("other-server", "get_balance"); ok {
		t.Error("a server with no entry must be unclassified")
	}
}

// The result must not depend on Go's random map order, or a tool's bits could change
// between runs of the same daemon.
func TestToolLabelsAreDeterministic(t *testing.T) {
	c := labelled()
	first, _ := c.ToolLabels("bank", "get_balance")
	for i := 0; i < 50; i++ {
		got, _ := c.ToolLabels("bank", "get_balance")
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d: %+v, first %+v", i, got, first)
		}
	}
}

// An unknown label sets no bit and a bad pattern matches nothing. Both would fail open
// silently, so both are configuration errors.
func TestValidateRejectsLabelsThatWouldFailOpen(t *testing.T) {
	for name, m := range map[string]map[string]map[string][]string{
		"unknown label":     {"bank": {"read_file": {"untrustd"}}},
		"bad pattern":       {"bank": {"get_[": {LabelReadOnly}}},
		"empty server name": {"": {"x": {LabelReadOnly}}},
	} {
		c := Default()
		c.MCPToolLabels = m
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "mcp_tool_labels") {
			t.Errorf("%s: error %q does not name the setting", name, err)
		}
	}
	c := labelled()
	if err := c.Validate(); err != nil {
		t.Errorf("valid labels rejected: %v", err)
	}
}

// The label file the AgentDojo measurement uses must load: a typo in it would fail the
// measurement script, or worse, measure with a classification nobody intended.
func TestShippedAgentDojoLabelsLoad(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "testdata", "agentdojo", "mcp-tool-labels.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.MCPToolLabels) != 4 {
		t.Errorf("servers labelled = %d, want the four AgentDojo suites", len(c.MCPToolLabels))
	}
	if tl, ok := c.ToolLabels("agentdojo-banking", "get_most_recent_transactions"); !ok || !tl.Untrusted || !tl.Sensitive {
		t.Errorf("transactions = %+v ok=%v; counterparty-written subjects make them untrusted as well as sensitive", tl, ok)
	}
}
