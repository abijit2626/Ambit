#!/usr/bin/env bash
# Waits on a Wazuh manager for an alert from a given rule, for the M1 exit tests that end with
# "rule N fires": D4 (100234), D7 (100314), D12 (100270) and the agent-disconnected rule 504.
set -euo pipefail

ALERTS=${ALERTS:-/var/ossec/logs/alerts/alerts.json}

die() { echo "expect-alert: $*" >&2; exit 1; }
say() { echo "expect-alert: $*"; }

usage() {
  cat >&2<<'USAGE'
Wait for an alert on this Wazuh manager and say whether it arrived in time.

  sudo ./scripts/expect-alert.sh --rule 100314 --agent volunteer-laptop --timeout 900
  sudo ./scripts/expect-alert.sh --rule 100270 --rule 100271 --agent volunteer-laptop

Start it first, then cause the condition (stop ambitd, edit a managed-settings key, mutate a
test MCP server, stop the Wazuh agent). It notes where alerts.json ends when it starts and looks
only at what is written after that, so an alert from an earlier test cannot pass this one. Do the
action before starting it and you may miss the alert.

  --rule ID      a rule id to wait for; repeat it to accept any of several
  --agent NAME   only count alerts from the agent with this name (recommended: on a manager
                 with several endpoints, a different one firing the same rule proves nothing)
  --timeout SEC  give up after this long (default 900). SCA checks run on the policy's scan
                 interval, so D7 and D12 can take as long as that interval
  --file PATH    the alerts file (default /var/ossec/logs/alerts/alerts.json, or $ALERTS)

Prints the first matching alert's time and rule description and exits 0; exits 1 on a timeout
with the rule ids that did appear in the meantime, which says whether the manager saw anything
at all; exits 2 on a usage error. Needs alerts.json to be on (Wazuh writes it by default;
<jsonout_output> in ossec.conf).

Matching is on the rule id and the agent name fields of each JSON line, with grep and no jq,
because a manager does not reliably have jq.
USAGE
  exit 2
}

rules=() agent="" timeout=900
while [ $# -gt 0 ]; do
  case "$1" in
    --rule) [ $# -ge 2 ] || usage; rules+=("$2"); shift 2 ;;
    --agent) [ $# -ge 2 ] || usage; agent="$2"; shift 2 ;;
    --timeout) [ $# -ge 2 ] || usage; timeout="$2"; shift 2 ;;
    --file) [ $# -ge 2 ] || usage; ALERTS="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ ${#rules[@]} -gt 0 ] || { echo "--rule is required" >&2; usage; }
for r in "${rules[@]}"; do
  case "$r" in ''|*[!0-9]*) echo "--rule takes a numeric rule id, got '$r'" >&2; usage ;; esac
done
case "$timeout" in ''|*[!0-9]*) echo "--timeout takes whole seconds, got '$timeout'" >&2; usage ;; esac
[ "$timeout" -gt 0 ] || { echo "--timeout must be greater than zero" >&2; usage; }
case "$agent" in *[!A-Za-z0-9._-]*) echo "--agent takes a plain agent name (letters, digits, . _ -), got '$agent'" >&2; usage ;; esac

[ -f "$ALERTS" ] || die "no alerts file at $ALERTS: run this on the Wazuh manager, and check that <jsonout_output> is yes in ossec.conf"

# "rule":{...,"id":"100314",...}: the rule object, so an agent whose id is 100314 cannot match.
alt=$(printf '%s|' "${rules[@]}")
alt=${alt%|}
rule_re="\"rule\":\\{[^}]*\"id\":\"($alt)\""
agent_re=""
[ -z "$agent" ] || agent_re="\"agent\":\\{[^}]*\"name\":\"$agent\""

size() { wc -c < "$ALERTS" | tr -d ' '; }

offset=$(size)
start=$(date +%s)
say "listening from byte $offset of $ALERTS for rule ${rules[*]}${agent:+ from agent $agent}, up to ${timeout}s"

seen=""
chunk=$(mktemp)
trap 'rm -f "$chunk" "$chunk.whole"' EXIT
while :; do
  now_size=$(size)
  # alerts.json is rotated daily; a smaller file is a new one, read from its beginning.
  if [ "$now_size" -lt "$offset" ]; then offset=0; fi
  if [ "$now_size" -gt "$offset" ]; then
    tail -c +"$((offset + 1))" "$ALERTS" | head -c "$((now_size - offset))" > "$chunk"
    take=$((now_size - offset))
    # Only whole lines: a line Wazuh is still writing is read on the next pass.
    if [ "$(tail -c 1 "$chunk" | od -An -c | tr -d ' ')" != '\n' ]; then
      take=$((take - $(tail -n 1 "$chunk" | wc -c | tr -d ' ')))
      head -c "$take" "$chunk" > "$chunk.whole"
      mv "$chunk.whole" "$chunk"
    fi
    offset=$((offset + take))
    new=$(cat "$chunk")
    hit=$(printf '%s\n' "$new" | grep -E "$rule_re" || true)
    if [ -n "$hit" ] && [ -n "$agent_re" ]; then
      hit=$(printf '%s\n' "$hit" | grep -E "$agent_re" || true)
    fi
    if [ -n "$hit" ]; then
      first=$(printf '%s\n' "$hit" | head -1)
      ts=$(printf '%s\n' "$first" | sed -n 's/.*"timestamp":"\([^"]*\)".*/\1/p' | head -1)
      desc=$(printf '%s\n' "$first" | sed -n 's/.*"rule":{[^}]*"description":"\([^"]*\)".*/\1/p' | head -1)
      say "PASS after $(( $(date +%s) - start ))s: ${ts:-?}  ${desc:-?}"
      exit 0
    fi
    seen="$seen
$(printf '%s\n' "$new" | sed -n 's/.*"rule":{[^}]*"id":"\([0-9]*\)".*/\1/p')"
  fi
  if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
    others=$(printf '%s\n' "$seen" | grep -E '^[0-9]+$' | sort | uniq -c | sort -rn | head -8 | awk '{printf "%s(x%s) ", $2, $1}' || true)
    echo "expect-alert: FAIL: no alert from rule ${rules[*]}${agent:+ for agent $agent} within ${timeout}s" >&2
    if [ -n "$others" ]; then
      echo "expect-alert: the manager did write other alerts meanwhile: $others" >&2
    else
      echo "expect-alert: the manager wrote no alerts at all meanwhile; is the agent connected and the rule file loaded?" >&2
    fi
    exit 1
  fi
  sleep 1
done
