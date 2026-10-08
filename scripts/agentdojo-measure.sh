#!/usr/bin/env bash
# Measure ambit against AgentDojo's published run logs.
#
#   ./scripts/agentdojo-measure.sh claude-3-7-sonnet-20250219
#   ./scripts/agentdojo-measure.sh gpt-4o-2024-05-13/banking -min-run-recall 0.5
#
# Each argument before the first flag names a directory under AgentDojo's runs/ (a model,
# or model/suite). The script sparse-fetches only those directories from
# github.com/ethz-spylab/agentdojo, converts them with agentdojo-convert and replays them
# with ambit-replay; flags after the names go to ambit-replay. Nothing is executed from
# the fetched repository: it is read as JSON data only.
#
# Pin AGENTDOJO_REF to a commit for a number someone else can reproduce exactly; the
# default follows the repository's default branch, which can change under you.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO=${AGENTDOJO_REPO:-https://github.com/ethz-spylab/agentdojo}
REF=${AGENTDOJO_REF:-HEAD}

names=()
while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do names+=("$1"); shift; done
if [ ${#names[@]} -eq 0 ]; then
  echo "usage: $0 <model[/suite]>... [ambit-replay flags]" >&2
  exit 1
fi
for n in "${names[@]}"; do
  case "$n" in *..*|/*) echo "refusing path '$n': names are relative to runs/" >&2; exit 1 ;; esac
done

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT

(cd "$ROOT" && go build -o "$D/agentdojo-convert" ./cmd/agentdojo-convert && go build -o "$D/ambit-replay" ./cmd/ambit-replay)

git clone -q --filter=blob:none --no-checkout "$REPO" "$D/agentdojo"
paths=()
for n in "${names[@]}"; do paths+=("runs/$n"); done
git -C "$D/agentdojo" sparse-checkout set --no-cone "${paths[@]}"
git -C "$D/agentdojo" checkout -q "$REF"
echo "agentdojo-measure: $REPO at $(git -C "$D/agentdojo" rev-parse --short HEAD)" >&2

inputs=()
for p in "${paths[@]}"; do
  [ -d "$D/agentdojo/$p" ] || { echo "no such runs directory upstream: $p" >&2; exit 1; }
  inputs+=("$D/agentdojo/$p")
done
"$D/agentdojo-convert" -out "$D/converted" "${inputs[@]}"
"$D/ambit-replay" "$@" "$D/converted"
