#!/usr/bin/env bash
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
