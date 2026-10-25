package doctor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const addr = "127.0.0.1:7777"

func file(t *testing.T, raw string) File {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return File{Path: "test.json", Settings: m}
}

func level(fs []Finding, check string) string {
	for _, f := range fs {
		if f.Check == check {
			return f.Level
		}
	}
	return ""
}

func bundle(t *testing.T) File {
	t.Helper()
	name := "managed-settings.m0.json"
	if runtime.GOOS == "windows" {
		name = "managed-settings.m0.windows.json"
	}
	files, problems := Load([]string{filepath.Join("..", "..", "deploy", "claude-code", name)})
	if len(problems) > 0 || len(files) != 1 {
		t.Fatalf("load the shipped bundle: %v", problems)
	}
	return files[0]
}

func TestTheShippedBundlePasses(t *testing.T) {
	fs := Check([]File{bundle(t)}, addr, true)
	for _, check := range []string{"hooks", "session_start", "sandbox", "otel"} {
		if got := level(fs, check); got != OK {
			t.Errorf("%s = %s, want ok: %+v", check, got, fs)
		}
	}
}

func TestSandboxWithoutLoopbackFails(t *testing.T) {
	user := file(t, `{"sandbox":{"enabled":true,"network":{"allowedDomains":["github.com"]}}}`)
	fs := Check([]File{user}, addr, true)
	if got := level(fs, "sandbox"); got != Fail {
		t.Errorf("sandbox = %s, want fail: the proxy refuses 127.0.0.1 (blocker 7)", got)
	}
}

// The M0 bundle carries 127.0.0.1 in the sandbox allowlist, so a managed endpoint passes whatever its own
// settings say, as long as they do not replace the list (a managed entry is merged, not overridden).
func TestSandboxWithTheBundlesLoopbackPasses(t *testing.T) {
	user := file(t, `{"sandbox":{"enabled":true,"network":{"allowedDomains":["github.com"]}}}`)
	if got := level(Check([]File{bundle(t), user}, addr, true), "sandbox"); got != OK {
		t.Errorf("sandbox with the bundle's 127.0.0.1 entry = %s, want ok", got)
	}
	ok := file(t, `{"sandbox":{"enabled":true,"network":{"allowedDomains":["127.0.0.1"]}}}`)
	if got := level(Check([]File{ok}, addr, true), "sandbox"); got != OK {
		t.Errorf("sandbox with 127.0.0.1 allowed = %s, want ok", got)
	}
}

func TestHooksPointingElsewhereFail(t *testing.T) {
	f := file(t, `{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"http","url":"http://127.0.0.1:9999/hook"}]}]}}`)
	fs := Check([]File{f}, addr, false)
	if got := level(fs, "hooks"); got != Fail {
		t.Errorf("hooks = %s, want fail", got)
	}
	if got := level(fs, "session_start"); got != Warn {
		t.Errorf("session_start = %s, want warn", got)
	}
	if got := level(fs, "otel"); got != "" {
		t.Errorf("otel checked although the receiver is off: %s", got)
	}
}

func TestProtobufExporterFails(t *testing.T) {
	f := file(t, `{"env":{"OTEL_EXPORTER_OTLP_PROTOCOL":"grpc"}}`)
	if got := level(Check([]File{bundle(t), f}, addr, true), "otel"); got != Fail {
		t.Errorf("otel = %s, want fail for grpc", got)
	}
}

func TestNoSettingsFails(t *testing.T) {
	if got := level(Check(nil, addr, false), "settings"); got != Fail {
		t.Errorf("settings = %s, want fail", got)
	}
}

func TestBrokenJSONIsReported(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, problems := Load([]string{p, filepath.Join(t.TempDir(), "absent.json")})
	if len(files) != 0 || len(problems) != 1 || problems[0].Level != Fail {
		t.Errorf("files %d, problems %+v: want one fail for the broken file and nothing for the absent one", len(files), problems)
	}
}

func TestMainFailsWhenAmbitdIsDown(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, []byte(`{"hook_addr":"127.0.0.1:1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := Main([]string{"-config", cfg, "-json"}, &out, &errb)
	if code != 1 || !strings.Contains(out.String(), `"check": "ambitd"`) {
		t.Errorf("exit %d, output %s %s: want 1 with an ambitd finding", code, out.String(), errb.String())
	}
}
