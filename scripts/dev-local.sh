#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AMBIT_DIR="${AMBIT_DIR:-$HOME/.ambit}"
CONFIG="$AMBIT_DIR/config.json"
EVENTS="$AMBIT_DIR/events.jsonl"
TRAJECTORY="$AMBIT_DIR/trajectory.jsonl"
HOOK_PORT="${HOOK_PORT:-7777}"
OTLP_PORT="${OTLP_PORT:-4318}"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
BIN="$AMBIT_DIR/ambitd"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }

status() {
  bold "ambitd local status"
  echo
  if pgrep -f "$BIN" >/dev/null 2>&1; then
    echo "  process:    running (pid $(pgrep -f "$BIN" | head -1))"
  else
    echo "  process:    not running"
  fi
  echo "  config:     $CONFIG"

  if [ ! -f "$TRAJECTORY" ]; then
    echo "  collected:  nothing yet"
    return 0
  fi

  local total crossed
  total=$(wc -l < "$TRAJECTORY" | tr -d ' ')
  crossed=0
  [ -f "$EVENTS" ] && crossed=$(wc -l < "$EVENTS" | tr -d ' ')

  echo "  spool:      $total events ($TRAJECTORY)"
  echo "  crossed:    $crossed events ($EVENTS)"

  if [ "$total" -gt 0 ]; then
    awk -v t="$total" -v c="$crossed" 'BEGIN{printf "  fraction:   %.2f%% of all events crossed\n", (c/t)*100}'
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$TRAJECTORY" "$EVENTS" <<'PY'
import json, sys, collections
traj, ev = sys.argv[1], sys.argv[2]

tool_kinds = {"tool_pre", "tool_post"}
tool_total = 0
kinds = collections.Counter()
sources = collections.Counter()
for line in open(traj, errors="replace"):
    try:
        d = json.loads(line)
    except Exception:
        continue
    k = d.get("kind", "?")
    src = d.get("source", "?")
    kinds[k] += 1
    sources[src] += 1
    if k in tool_kinds and src == "hook":
        tool_total += 1

tool_crossed = 0
reasons = collections.Counter()
try:
    for line in open(ev, errors="replace"):
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("kind") in tool_kinds:
            tool_crossed += 1
            if d.get("policy_decision"):
                reasons["policy_decision"] += 1
            elif d.get("prov_edge_count"):
                reasons["provenance_edge"] += 1
            elif d.get("path_zone") in ("credential", "system"):
                reasons["severe_zone"] += 1
            elif d.get("secret_hit_kinds"):
                reasons["secret_hit"] += 1
            elif d.get("bash_command_class") in ("network", "publish", "vcs_write"):
                reasons["network_command"] += 1
            elif d.get("tool_mcp_server"):
                reasons["mcp_risk"] += 1
            elif d.get("prov_fp_notable"):
                reasons["notable_fingerprint"] += 1
            else:
                reasons["sampled_or_other"] += 1
except FileNotFoundError:
    pass

print()
print("  TOOL EVENTS (the number the design's 2-5% estimate is about)")
if tool_total:
    pct = tool_crossed / tool_total * 100
    print(f"    {tool_crossed} of {tool_total} crossed = {pct:.2f}%")
    if pct > 10:
        print("    ^ well above the 2-5% estimate. The filter criteria in")
        print("      docs/04-data-model.md need tightening before M1.")
    elif tool_total < 500:
        print("    ^ small sample. Keep it running for a full day of real work.")
else:
    print("    no tool events yet")

if reasons:
    print()
    print("  WHY THEY CROSSED")
    for r, n in reasons.most_common():
        print(f"    {r:24} {n}")

print()
print("  STREAMS (both non-zero once OTel is flowing; exactly one")
print("   silent is the D7 discrepancy)")
for s, n in sources.most_common():
    print(f"    {s:24} {n}")

print()
print("  ALL EVENT KINDS")
for k, n in kinds.most_common():
    print(f"    {k:24} {n}")
PY
  fi

  echo
  echo "  Leak check on the Wazuh-bound sink (should all be clean):"
  local home_base
  home_base=$(basename "$HOME")
  for s in "$HOME" "/$home_base/" ".ssh" ".aws"; do
    if [ -f "$EVENTS" ] && grep -qF "$s" "$EVENTS" 2>/dev/null; then
      warn "    LEAKED: $s"
    else
      echo "    clean:  $s"
    fi
  done
}

uninstall() {
  bold "Removing the local ambitd setup"
  pkill -f "$BIN" 2>/dev/null || true
  if [ -f "$SETTINGS.ambit-backup" ]; then
    mv "$SETTINGS.ambit-backup" "$SETTINGS"
    echo "  restored $SETTINGS from backup"
  else
    warn "  no backup found; remove the ambit hooks from $SETTINGS by hand"
  fi
  echo
  echo "  Left in place so you do not lose collected data:"
  echo "    $AMBIT_DIR"
  echo "  Delete it when you are done:  rm -rf $AMBIT_DIR"
}

usage() {
  cat <<'USAGE'
Set up ambitd against your own Claude Code sessions, on your own machine.

Why: the M0 exit criterion that blocks everything downstream is the MEASURED
INTERESTING FRACTION — what share of real tool calls are security-relevant
enough to cross to Wazuh. The design estimates 2-5%; the synthetic test mix
gives ~1%. If your real work comes back at 30%, the filter criteria in
docs/04-data-model.md tighten before M1, and every rule threshold in
docs/03-detection.md gets set from data instead of from a guess.

You are the cheapest source of that number, and this needs no Wazuh, no MDM and
no cohort.

This uses USER-SCOPE settings (~/.claude/settings.json), not managed settings.
Nothing here is fleet-wide and nothing needs admin. It is safe because ambitd is
inert: every hook response is {}, which means "no opinion", so Claude Code's
permission pipeline behaves exactly as it would with no hook installed.

Usage:
  ./scripts/dev-local.sh            # install
  ./scripts/dev-local.sh --status    # what has been collected so far
  ./scripts/dev-local.sh --uninstall # remove
USAGE
}

case "${1:-install}" in
  --status|status) status; exit 0 ;;
  --uninstall|uninstall) uninstall; exit 0 ;;
  --help|-h) usage; exit 0 ;;
esac

bold "Building ambitd"
mkdir -p "$AMBIT_DIR"
chmod 700 "$AMBIT_DIR"
( cd "$ROOT" && go build -ldflags "-X main.version=dev-local" -o "$BIN" ./cmd/ambitd )
echo "  $BIN"

bold "Writing config"
cat > "$CONFIG" <<EOF
{
  "hook_addr": "127.0.0.1:$HOOK_PORT",
  "otlp_addr": "127.0.0.1:$OTLP_PORT",
  "otlp_enabled": true,
  "events_path": "$EVENTS",
  "trajectory_path": "$TRAJECTORY",
  "fingerprint_key_path": "$AMBIT_DIR/fingerprint.key",
  "baseline_dir": "$AMBIT_DIR/baselines",
  "endpoint_id": "ep_$(hostname | tr -cd 'a-zA-Z0-9' | tr 'A-Z' 'a-z' | cut -c1-16)",
  "user_id": "$(id -un)",
  "org_id": "local",
  "trusted_repo_paths": ["$HOME/src", "$ROOT"],
  "trusted_mcp_servers": [],
  "sample_rate": 0.005,
  "health_seconds": 60,
  "latency_budget_ms": 5,
  "enforce": false
}
EOF
chmod 600 "$CONFIG"
echo "  $CONFIG"

bold "Merging hooks into $SETTINGS"
mkdir -p "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
if [ -f "$SETTINGS.ambit-backup" ]; then
  echo "  backup already exists, keeping it: $SETTINGS.ambit-backup"
else
  cp "$SETTINGS" "$SETTINGS.ambit-backup"
  echo "  backed up to $SETTINGS.ambit-backup"
fi

python3 - "$SETTINGS" "$HOOK_PORT" "$OTLP_PORT" <<'PY'
import json, sys
path, hook_port, otlp_port = sys.argv[1], sys.argv[2], sys.argv[3]
url = f"http://127.0.0.1:{hook_port}/hook"

with open(path) as f:
    settings = json.load(f)

entry = {"type": "http", "url": url}

no_matcher = {"UserPromptSubmit"}
events = [
    "PreToolUse", "PostToolUse", "PostToolUseFailure",
    "PermissionRequest", "PermissionDenied",
    "SessionStart", "SessionEnd", "UserPromptSubmit",
    "InstructionsLoaded", "ConfigChange",
    "SubagentStart", "SubagentStop", "PreCompact", "PostCompact",
]

hooks = settings.setdefault("hooks", {})
for ev in events:
    block = {"hooks": [entry]} if ev in no_matcher else {"matcher": ".*", "hooks": [entry]}
    existing = hooks.setdefault(ev, [])
    if not any(
        any(h.get("url") == url for h in e.get("hooks", []))
        for e in existing if isinstance(e, dict)
    ):
        existing.append(block)

env = settings.setdefault("env", {})
env.update({
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{otlp_port}",
})

with open(path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")

print(f"  added {len(events)} hook events + OTel env")
PY

bold "Starting ambitd"
pkill -f "$BIN" 2>/dev/null || true
nohup "$BIN" -config "$CONFIG" > "$AMBIT_DIR/ambitd.log" 2>&1 &
sleep 1

if curl -sf "http://127.0.0.1:$HOOK_PORT/healthz" >/dev/null 2>&1; then
  echo "  running, hook endpoint healthy on 127.0.0.1:$HOOK_PORT"
else
  warn "  ambitd did not come up; see $AMBIT_DIR/ambitd.log"
  tail -20 "$AMBIT_DIR/ambitd.log" || true
  exit 1
fi

cat <<EOF

$(bold "Done. Now just work normally.")

Start Claude Code sessions and use them as you always would. ambitd returns no
decision, so nothing about those sessions changes. After a day of real work:

    ./scripts/dev-local.sh --status

That prints the interesting fraction over tool events, which is the M0 exit
criterion, plus why each event crossed so you can see which criterion drives the
volume.

Notes:

  - ambitd does not restart itself. After a reboot, re-run this script.
  - The spool ($TRAJECTORY) holds everything, including prompt text. It is
    chmod 600 under $AMBIT_DIR and never leaves the machine.
  - The Wazuh-bound sink ($EVENTS) holds only the filtered slice, with paths as
    keyed digests. --status leak-checks it.
  - To remove:  ./scripts/dev-local.sh --uninstall

EOF
