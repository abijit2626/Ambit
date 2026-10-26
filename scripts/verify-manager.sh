#!/usr/bin/env bash
# Runs the recorded fixtures through the real rule engine on a Wazuh manager and compares what
# fires with deploy/wazuh/fixtures/*.winners. Run it on the manager after copying the rules in
# (cohort checklist, "Stand up the manager", step 3). The winners were recorded on a 4.14.8
# container, so a difference here is a difference between that engine and this manager.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FX=$ROOT/deploy/wazuh/fixtures
RULES_SRC=$ROOT/deploy/wazuh/rules

LOGTEST=${LOGTEST:-/var/ossec/bin/wazuh-logtest}
RULES_DST=${RULES_DST:-/var/ossec/etc/rules}
OSSEC_LOG=${OSSEC_LOG:-/var/ossec/logs/ossec.log}

die() { echo "verify-manager: $*" >&2; exit 1; }

usage() {
  cat >&2<<'USAGE'
Run the recorded fixtures through the Wazuh rule engine on this manager and compare.

  sudo ./scripts/verify-manager.sh              # every fixture that has a .winners file
  sudo ./scripts/verify-manager.sh d5-matrix    # just the named fixtures

For each fixture it feeds the events to one wazuh-logtest process, takes the id of the rule
that alerted on each event (- when none did) and the decoder that matched, and compares with
deploy/wazuh/fixtures/<name>.winners. It also checks that:

  - the rule files in /var/ossec/etc/rules are the repository's, byte for byte, so the result
    is about the rules you meant to test;
  - the matched decoder is json on every event;
  - the manager log has no "Too many fields for JSON decoder".

Prints one line per fixture, then each difference as "line N: expected X, manager said Y".
Exit status 0 when everything agrees, 1 when anything differs, 2 on a usage error.

What it does not cover: the correlation fixtures (g-*.jsonl), which need events spread over
time, and the syscheck and SCA parent SIDs, which no logtest event exercises. Those stay in the
checklist as manual steps. A difference is not necessarily a rule bug: the winners come from a
container, and the first thing to rule out is that this manager runs another version.

Environment: LOGTEST, RULES_DST and OSSEC_LOG override the default Wazuh paths.
USAGE
  exit 2
}

case "${1:-}" in -h|--help) usage ;; esac

[ -x "$LOGTEST" ] || die "no wazuh-logtest at $LOGTEST: run this on the Wazuh manager (LOGTEST=... overrides the path)"
[ -d "$FX" ] || die "missing $FX; run this from a checkout of the repository"

fail=0

# The rule files on the manager must be the ones in the repository.
for src in "$RULES_SRC"/ambit_*.xml; do
  dst=$RULES_DST/$(basename "$src")
  if [ ! -f "$dst" ]; then
    echo "FAIL rules: $dst is missing; copy deploy/wazuh/rules/ambit_*.xml there and restart the manager"
    fail=1
  elif ! cmp -s "$src" "$dst"; then
    echo "FAIL rules: $dst differs from the repository's $(basename "$src")"
    fail=1
  fi
done

if [ -f "$OSSEC_LOG" ] && grep -qi "too many fields" "$OSSEC_LOG"; then
  echo "FAIL manager log: $OSSEC_LOG contains \"Too many fields for JSON decoder\""
  fail=1
fi

# One line per event: "<decoder> <rule id or ->". An event with no Phase 3 got no rule.
results() {
  "$LOGTEST" 2>&1 < "$1" | awk '
    function flush() { if (n > 0) print (dec == "" ? "none" : dec), id }
    /^\*\*Phase 1:/ { flush(); n++; id = "-"; dec = ""; phase = 1; next }
    /^\*\*Phase 2:/ { phase = 2; next }
    /^\*\*Phase 3:/ { phase = 3; next }
    phase == 2 && /^[ \t]+name: / { v = $0; sub(/^[ \t]+name: /, "", v); gsub(/\047/, "", v); if (dec == "") dec = v; next }
    phase == 3 && /^[ \t]+id: /   { v = $0; sub(/^[ \t]+id: /, "", v); gsub(/\047/, "", v); id = v; next }
    END { flush() }'
}

if [ $# -eq 0 ]; then
  set --
  for w in "$FX"/*.winners; do set -- "$@" "$(basename "$w" .winners)"; done
fi

for name in "$@"; do
  fixture=$FX/$name.jsonl
  want_file=$FX/$name.winners
  if [ ! -f "$fixture" ] || [ ! -f "$want_file" ]; then
    echo "unknown fixture '$name': needs $fixture and $want_file" >&2
    exit 2
  fi
  want=$(grep -v '^#' "$want_file")
  got=$(results "$fixture")
  events=$(grep -vc '^#' "$fixture" || true)
  have=$(printf '%s\n' "$got" | grep -c . || true)
  if [ "$have" != "$events" ]; then
    echo "FAIL $name: wazuh-logtest answered for $have of $events events; is the engine running?"
    fail=1
    continue
  fi

  bad=0 lineno=0 notjson=0
  while IFS= read -r exp <&3 && IFS=' ' read -r dec rule <&4; do
    lineno=$((lineno + 1))
    if [ "$dec" != "json" ]; then
      notjson=$((notjson + 1))
      [ "$notjson" -le 3 ] && echo "  $name line $lineno: decoder was '$dec', not json (is log_format json in effect?)"
    fi
    if [ "$exp" != "$rule" ]; then
      bad=$((bad + 1))
      echo "  $name line $lineno: expected $exp, manager said $rule"
    fi
  done 3< <(printf '%s\n' "$want") 4< <(printf '%s\n' "$got")

  if [ "$bad" -eq 0 ] && [ "$notjson" -eq 0 ]; then
    echo "ok   $name: $events events agree with the recorded winners"
  else
    echo "FAIL $name: $bad of $events events differ, $notjson not decoded as json"
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "verify-manager: every fixture agrees with the recorded winners"
  exit 0
fi
echo "verify-manager: differences found (above)" >&2
exit 1
