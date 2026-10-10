package event

import (
	"encoding/json"
	"sort"
	"testing"
)

func b(v bool) *bool { return &v }

func fullEvent() *Event {
	drift := 0.87
	return &Event{
		EventID: "01JD", TS: "2026-09-27T11:50:03.412Z", IngestedAt: "2026-09-27T11:50:04Z",
		Source: SourceHook, SchemaV: SchemaVersion, Kind: KindToolPre,
		Endpoint: Endpoint{EndpointID: "ep_1", HostnameDigest: "hmac:h", OS: "darwin", AmbitdVersion: "0.1.0"},
		Actor:    Actor{UserID: "u_1", OrgID: "o_1"},
		Agent: Agent{
			Kind: "claude-code", Version: "2.1.271", Entrypoint: "cli", Model: "claude-opus-5",
			PermissionMode: "default", CWDDigest: "hmac:c",
			Repo:    Repo{RemoteDigest: "hmac:r", Branch: "main", Dirty: true},
			Sandbox: Sandbox{Enabled: true, StrictAllowlist: true},
		},
		Session: Session{SessionID: "s_1", PromptID: "p_1", Sequence: 1487, AgentType: "Explore", ParentSessionID: "s_0"},
		Tool: &Tool{
			Name: "Bash", UseID: "toolu_1", InputDigest: "hmac:i", ResultDigest: "hmac:o", ResultBytes: 18422,
			MCP: &MCP{Server: "github", Tool: "create_issue", MetadataHash: "sha256:m", Trust: "external",
				Annotations: Annotations{ReadOnlyHint: b(false), DestructiveHint: b(true), IdempotentHint: b(false), OpenWorldHint: b(true)},

				BaselineState: MCPStateDrift, PrevMetadataHash: "sha256:p",
				ChangedFields: []string{"description"}, ScanClasses: []string{"hidden_instruction"},
				ScanRules: []string{"hidden.ignore_previous"}, ToolCount: 12, DriftCount: 1,
				Trigger: "tools_list", ServerVersion: "1.4.0", CallsObserved: 12},
			Bash: &Bash{Argv0: "curl", CommandClass: "network", CommandDigest: "hmac:b"},
			Paths: []PathRef{
				{PathDigest: "hmac:p1", Zone: ZoneWorkdir, Op: "read"},
				{PathDigest: "hmac:p2", Zone: ZoneCredential, Op: "read"},
				{PathDigest: "hmac:p3", Zone: ZoneUntrusted, Op: "read"},
			},
			InputFeatures: &Features{SecretHits: []SecretHit{{Kind: "github_token", Count: 2}, {Kind: "aws_key", Count: 1}}},
		},
		Provenance: Provenance{
			Taint: []string{"web:hmac:d", "mcp:github"}, IngestRefs: []string{"01JA", "01JB"},
			Edges: []Edge{
				{FromEvent: "01JA", MatchClass: "shingle", Confidence: 0.3},
				{FromEvent: "01JB", MatchClass: "domain", Confidence: 0.9},
			},
			FPNotable: "hmac:f", FPRole: "output",
		},
		R2:     R2{A: true, B: true, C: false, SetBy: "01JA", Transition: true},
		Policy: Policy{Decision: DecisionDeny, Reason: "r2 third bit", RuleIDs: []string{"r2.egress.deny", "prov.domain.match"}, BundleVersion: "2026-09-20.3", LatencyUS: 1840, Shadow: true},
		Scores: Scores{GoalDrift: &drift, DriftScorerV: "v1"},
		Config: &ConfigInfo{Source: "user_settings", LoadReason: "session_start", PathDigest: "hmac:cfg", Zone: ZoneHome, Trusted: false},
		Health: &Health{Status: "ok", QueueDepth: 3, DroppedEvents: 0},
	}
}

func fieldCount(t *testing.T, s *SIEMEvent) (int, []string) {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return len(m), keys
}

func TestSIEMEventFieldBudgetPerKind(t *testing.T) {
	const budget = 55

	cases := []struct {
		name  string
		event *Event
	}{
		{"tool_pre_bash", bashToolEvent()},
		{"tool_pre_mcp", mcpToolEvent()},
		{"mcp_list", mcpListEvent()},
		{"session_start", sessionStartEvent()},
		{"config_change", configEvent()},
		{"ambitd_health", healthEvent()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, keys := fieldCount(t, Flatten(c.event))
			if n > budget {
				t.Errorf("%s event has %d fields, budget is %d: %v", c.name, n, budget, keys)
			}
			t.Logf("%s: %d fields (budget %d)", c.name, n, budget)
		})
	}
}

func TestSIEMEventFieldCeiling(t *testing.T) {
	const ceiling = 70
	n, keys := fieldCount(t, Flatten(fullEvent()))
	if n > ceiling {
		t.Errorf("union of all blocks has %d fields, ceiling is %d: %v", n, ceiling, keys)
	}
	t.Logf("union field count: %d (ceiling %d)", n, ceiling)
}

func TestFlattenNoNestedObjects(t *testing.T) {
	raw, err := json.Marshal(Flatten(fullEvent()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k, v := range m {
		switch tv := v.(type) {
		case map[string]any:
			t.Errorf("field %q is a nested object; flattened events must be scalar or array-of-scalar", k)
		case []any:
			for i, elem := range tv {
				if _, bad := elem.(map[string]any); bad {
					t.Errorf("field %q[%d] is an object; Wazuh's JSON decoder does not support an array of objects", k, i)
				}
			}
		}
	}
}

func TestFlattenPicksHighestSeverityPath(t *testing.T) {
	s := Flatten(fullEvent())
	if s.PathZone != ZoneCredential {
		t.Errorf("PathZone = %q, want %q: credential must outrank untrusted and workdir", s.PathZone, ZoneCredential)
	}
	if s.PathDigest != "hmac:p2" {
		t.Errorf("PathDigest = %q, want the credential path's digest", s.PathDigest)
	}
	if s.PathCount != 3 {
		t.Errorf("PathCount = %d, want 3: cardinality must survive for D2", s.PathCount)
	}
}

func TestFlattenCarriesTheInstructionLoadReason(t *testing.T) {
	e := configEvent()
	e.Kind = KindInstructionsLoaded
	e.Config = &ConfigInfo{LoadReason: "file_read", PathDigest: "hmac:i", Zone: ZoneUntrusted}
	s := Flatten(e)
	if s.ConfigLoadReason != "file_read" {
		t.Errorf("ConfigLoadReason = %q, want file_read", s.ConfigLoadReason)
	}
	if s.ConfigSource != "" {
		t.Errorf("ConfigSource = %q: an instructions_loaded event has none, and the reason must not be smuggled into it", s.ConfigSource)
	}
}

func TestFlattenPicksHighestConfidenceEdge(t *testing.T) {
	s := Flatten(fullEvent())
	if s.ProvEdgeClass != "domain" {
		t.Errorf("ProvEdgeClass = %q, want \"domain\" (confidence 0.9 beats 0.3)", s.ProvEdgeClass)
	}
	if s.ProvEdgeConfidence != 0.9 {
		t.Errorf("ProvEdgeConfidence = %v, want 0.9", s.ProvEdgeConfidence)
	}
	if s.ProvEdgeCount != 2 {
		t.Errorf("ProvEdgeCount = %d, want 2", s.ProvEdgeCount)
	}
}

func TestFlattenDropsRawFingerprints(t *testing.T) {
	e := fullEvent()
	e.Tool.InputFeatures.Domains = []string{"hmac:d1", "hmac:d2"}
	e.Tool.InputFeatures.Shingles = []string{"hmac:s1"}
	e.Tool.InputFeatures.HiEntropy = []string{"hmac:h1"}

	raw, err := json.Marshal(Flatten(e))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{"hmac:d1", "hmac:d2", "hmac:s1", "hmac:h1"} {
		if contains(string(raw), leaked) {
			t.Errorf("raw fingerprint %q leaked into the flattened event", leaked)
		}
	}
}

func TestFlattenNeverCarriesSecretValues(t *testing.T) {
	s := Flatten(fullEvent())
	want := []string{"aws_key", "github_token"}
	if len(s.SecretHitKinds) != len(want) {
		t.Fatalf("SecretHitKinds = %v, want %v", s.SecretHitKinds, want)
	}
	for i := range want {
		if s.SecretHitKinds[i] != want[i] {
			t.Errorf("SecretHitKinds[%d] = %q, want %q", i, s.SecretHitKinds[i], want[i])
		}
	}
}

func TestFlattenDropsOperationalFields(t *testing.T) {
	raw, _ := json.Marshal(Flatten(fullEvent()))
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, absent := range []string{"policy_latency_us", "latency_us", "ingest_refs", "cwd_digest", "hostname_digest", "repo_dirty", "r2_set_by"} {
		if _, present := m[absent]; present {
			t.Errorf("field %q should not cross to the SIEM", absent)
		}
	}
}

func TestFlattenPreservesAbsentAnnotations(t *testing.T) {
	e := fullEvent()
	e.Tool.MCP.Annotations = Annotations{}
	s := Flatten(e)
	if s.ToolMCPReadonlyHint != nil {
		t.Errorf("ToolMCPReadonlyHint = %v, want nil when the server advertised no hint", *s.ToolMCPReadonlyHint)
	}
	raw, _ := json.Marshal(s)
	if contains(string(raw), "tool_mcp_readonly_hint") {
		t.Error("absent annotation must be omitted from the wire form, not emitted as false")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func bashToolEvent() *Event {
	e := fullEvent()
	e.Config = nil
	e.Health = nil
	e.Scores = Scores{}
	e.Tool.MCP = nil
	return e
}

func mcpToolEvent() *Event {
	e := fullEvent()
	e.Config = nil
	e.Health = nil
	e.Scores = Scores{}
	e.Tool.Bash = nil
	e.Tool.Paths = nil
	e.Tool.Name = "mcp__github__create_issue"

	m := e.Tool.MCP
	m.BaselineState, m.PrevMetadataHash, m.Trigger, m.ServerVersion = "", "", "", ""
	m.ChangedFields, m.ScanClasses, m.ScanRules = nil, nil, nil
	m.ToolCount, m.NewCount, m.DriftCount, m.RemovedCount, m.CallsObserved = 0, 0, 0, 0, 0
	return e
}

func mcpListEvent() *Event {
	e := fullEvent()
	e.Kind = KindMCPList
	e.Source = SourceInterpose
	e.Config = nil
	e.Health = nil
	e.Scores = Scores{}
	e.Provenance = Provenance{}
	e.Tool.Bash = nil
	e.Tool.Paths = nil
	e.Tool.InputFeatures = nil
	e.Tool.Name = "mcp__github__create_issue"
	return e
}

func sessionStartEvent() *Event {
	e := fullEvent()
	e.Kind = KindSessionStart
	e.Tool = nil
	e.Config = nil
	e.Health = nil
	e.Provenance = Provenance{}
	e.Policy = Policy{}
	e.Scores = Scores{}
	return e
}

func configEvent() *Event {
	e := fullEvent()
	e.Kind = KindConfigChange
	e.Tool = nil
	e.Health = nil
	e.Provenance = Provenance{}
	e.Policy = Policy{}
	e.Scores = Scores{}
	return e
}

func healthEvent() *Event {
	e := fullEvent()
	e.Kind = KindAmbitdHealth
	e.Tool = nil
	e.Config = nil
	e.Session = Session{}
	e.Provenance = Provenance{}
	e.Policy = Policy{}
	e.Scores = Scores{}
	return e
}
