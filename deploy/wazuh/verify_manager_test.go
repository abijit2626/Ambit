package wazuh

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const verifyScript = "../../scripts/verify-manager.sh"

// The stub plays the part of wazuh-logtest in the output format scripts/record-winners.sh
// already parses (Phase 1, 2 and 3 headers, tab-indented name: and id: lines). It identifies
// the fixture by comparing its input with the files in FIXTURES and answers from that fixture's
// .winners file, so what is under test is the script's reading and comparing, not Wazuh.
// STUB_OVERRIDE="N:ID" changes the winner of event N, and STUB_DECODER changes the decoder.
const logtestStub = `#!/usr/bin/env bash
in=$(mktemp); cat > "$in"
winners=""
for f in "$FIXTURES"/*.jsonl; do
  w="${f%.jsonl}.winners"
  if [ -f "$w" ] && cmp -s "$f" "$in"; then winners=$w; break; fi
done
rm -f "$in"
[ -n "$winners" ] || { echo "stub: unknown fixture" >&2; exit 1; }
n=0
while read -r id; do
  n=$((n + 1))
  if [ -n "${STUB_OVERRIDE:-}" ] && [ "${STUB_OVERRIDE%%:*}" = "$n" ]; then id=${STUB_OVERRIDE#*:}; fi
  echo "**Phase 1: Completed pre-decoding."
  printf '\tfull event: '"'"'{}'"'"'\n'
  echo "**Phase 2: Completed decoding."
  printf '\tname: '"'"'%s'"'"'\n' "${STUB_DECODER:-json}"
  if [ "$id" != "-" ]; then
    echo "**Phase 3: Completed filtering (rules)."
    printf '\tid: '"'"'%s'"'"'\n' "$id"
    printf '\tlevel: '"'"'3'"'"'\n'
    echo "**Alert to be generated."
  fi
done < <(grep -v '^#' "$winners")
`

type manager struct {
	t        *testing.T
	dir      string
	rules    string
	logtest  string
	ossecLog string
}

func newManager(t *testing.T) *manager {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the script is for a Linux manager")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	m := &manager{t: t, dir: dir, rules: filepath.Join(dir, "rules"), logtest: filepath.Join(dir, "wazuh-logtest"), ossecLog: filepath.Join(dir, "ossec.log")}
	if err := os.MkdirAll(m.rules, 0o755); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("rules/ambit_*.xml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no rule files: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m.rules, filepath.Base(f)), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(m.logtest, []byte(logtestStub), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.ossecLog, []byte("2026/10/26 INFO: started\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *manager) run(env []string, args ...string) (string, error) {
	fx, err := filepath.Abs("fixtures")
	if err != nil {
		m.t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{verifyScript}, args...)...)
	cmd.Env = append(os.Environ(),
		"LOGTEST="+m.logtest, "RULES_DST="+m.rules, "OSSEC_LOG="+m.ossecLog, "FIXTURES="+fx)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestVerifyManagerParses(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if out, err := exec.Command(bash, "-n", verifyScript).CombinedOutput(); err != nil {
		t.Errorf("bash -n: %v\n%s", err, out)
	}
}

func TestVerifyManagerPassesWhenTheEngineAgreesWithTheRecordedWinners(t *testing.T) {
	m := newManager(t)
	out, err := m.run(nil)
	if err != nil {
		t.Fatalf("err=%v\n%s", err, out)
	}
	winners, _ := filepath.Glob("fixtures/*.winners")
	if len(winners) == 0 {
		t.Fatal("no .winners files")
	}
	for _, w := range winners {
		name := strings.TrimSuffix(filepath.Base(w), ".winners")
		if !strings.Contains(out, "ok   "+name+":") {
			t.Errorf("no ok line for %s:\n%s", name, out)
		}
	}
}

func TestVerifyManagerNamesTheEventWhoseWinnerDiffers(t *testing.T) {
	m := newManager(t)
	out, err := m.run([]string{"STUB_OVERRIDE=3:100999"}, "d5-matrix")
	if err == nil {
		t.Fatalf("a changed winner passed:\n%s", out)
	}
	if !strings.Contains(out, "d5-matrix line 3: expected ") || !strings.Contains(out, "manager said 100999") {
		t.Errorf("the difference is not named:\n%s", out)
	}
	if strings.Contains(out, "line 4:") {
		t.Errorf("an event that agrees was reported:\n%s", out)
	}
}

func TestVerifyManagerFailsWhenTheDecoderIsNotJSON(t *testing.T) {
	m := newManager(t)
	out, err := m.run([]string{"STUB_DECODER=ossec"}, "rules-alone")
	if err == nil || !strings.Contains(out, "not json") {
		t.Errorf("err=%v\n%s", err, out)
	}
}

func TestVerifyManagerFailsWhenTheRulesOnTheManagerAreNotTheRepositorys(t *testing.T) {
	m := newManager(t)
	files, _ := filepath.Glob(filepath.Join(m.rules, "ambit_*.xml"))
	if err := os.WriteFile(files[0], []byte("<group/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := m.run(nil, "rules-alone")
	if err == nil || !strings.Contains(out, "differs from the repository's") {
		t.Errorf("err=%v\n%s", err, out)
	}

	m = newManager(t)
	files, _ = filepath.Glob(filepath.Join(m.rules, "ambit_*.xml"))
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	out, err = m.run(nil, "rules-alone")
	if err == nil || !strings.Contains(out, "is missing") {
		t.Errorf("err=%v\n%s", err, out)
	}
}

func TestVerifyManagerFailsOnTooManyFieldsInTheManagerLog(t *testing.T) {
	m := newManager(t)
	if err := os.WriteFile(m.ossecLog, []byte("ERROR: Too many fields for JSON decoder\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := m.run(nil, "rules-alone")
	if err == nil || !strings.Contains(out, "Too many fields") {
		t.Errorf("err=%v\n%s", err, out)
	}
}

func TestVerifyManagerFailsWhenLogtestIsNotThere(t *testing.T) {
	m := newManager(t)
	if err := os.Remove(m.logtest); err != nil {
		t.Fatal(err)
	}
	out, err := m.run(nil)
	if err == nil || !strings.Contains(out, "no wazuh-logtest") {
		t.Errorf("err=%v\n%s", err, out)
	}
}

func TestVerifyManagerRejectsAnUnknownFixture(t *testing.T) {
	m := newManager(t)
	out, err := m.run(nil, "no-such-fixture")
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 2 {
		t.Errorf("err=%v\n%s", err, out)
	}
}
