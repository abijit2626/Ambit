#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
  cat >&2<<'USAGE'
Build the packets for a runbook rehearsal: the M1 exit criterion that someone OUTSIDE the
team executes a runbook against a sample alert.

  ./scripts/runbook-rehearsal.sh -o /tmp/rehearsal              # every runbook
  ./scripts/runbook-rehearsal.sh -o /tmp/rehearsal -r D4,D7     # just these

Writes two sibling directories under -o:
  analyst/      hand this over: a sample alert and the runbook for each detector, plus a
                feedback form. Nothing in it says what the right answer is.
  answer-key/   keep this: the rule each alert stands for, the fields the runbook claims
                it asserts, and the runbook's own escalation rules, to score against.

The alerts are assembled OFFLINE from the rules and the generated fixtures, in Wazuh's
alert shape. They are not what a manager emits. For a rehearsal that is meant to count,
regenerate the alert on a manager (docs/06-cohort-checklist.md says how) and swap it in.
Runbooks whose rules read Wazuh-internal alerts or correlate over time cannot be built
offline; answer-key/00-manifest.md lists them with the reason.
USAGE
}

out=""
only=""
while getopts "o:r:h" opt; do
  case "$opt" in
    o) out="$OPTARG" ;;
    r) only="$OPTARG" ;;
    h|*) usage; exit 2 ;;
  esac
done
if [ -z "$out" ]; then
  echo "usage: $0 -o <empty output dir> [-r D4,D7]" >&2
  exit 2
fi

case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

if [ -d "$out" ] && [ -n "$(ls -A "$out")" ]; then
  echo "refusing $out: it is not empty. Use a new directory." >&2
  exit 1
fi
mkdir -p "$out"

if ! log=$(cd "$ROOT" && AMBIT_REHEARSAL_DIR="$out" AMBIT_REHEARSAL_ONLY="$only" \
  go test ./deploy/wazuh -run '^TestWriteRehearsalPackets$' -count=1 -v 2>&1); then
  echo "$log" >&2
  echo "the packet generator failed" >&2
  exit 1
fi
echo "$log" | grep -E 'wrote [0-9]+ packet' >&2 || true

if [ ! -d "$out/analyst" ]; then
  echo "no packets were written" >&2
  exit 1
fi

echo
echo "packets for the analyst:"
for d in "$out"/analyst/*/; do
  [ -d "$d" ] && echo "  $(basename "$d")  ($(ls "$d" | grep -c '^alert-') alert(s))"
done
echo
echo "hand over:  $out/analyst"
echo "keep back:  $out/answer-key   (00-manifest.md lists runbooks with no packet, and why)"
