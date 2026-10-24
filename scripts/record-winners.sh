#!/usr/bin/env bash
# Re-records deploy/wazuh/fixtures/<name>.winners for each fixture named (default: every fixture that has a
# .winners file): one wazuh-logtest process per fixture on a fresh wazuh-manager 4.14.8 container, one event
# per line, and the id of the rule that matched each event (- when none did). TestWinnerModelAgreesWithWazuh
# compares the Go model against these files. Needs docker and network access to pull the image.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FX=$ROOT/deploy/wazuh/fixtures
RULES=${RULES:-$ROOT/deploy/wazuh/rules}
NAME=ambit-record-winners-$$
IMAGE=${IMAGE:-wazuh/wazuh-manager:4.14.8}

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker exec "$NAME" cp -a /var/ossec/data_tmp/exclusion/var/ossec/etc/internal_options.conf /var/ossec/etc/internal_options.conf
for f in "$RULES"/ambit_*.xml; do docker cp "$f" "$NAME":/var/ossec/etc/rules/; done
docker exec "$NAME" bash -c 'chown root:wazuh /var/ossec/etc/rules/ambit_*.xml; chmod 660 /var/ossec/etc/rules/ambit_*.xml'
docker exec "$NAME" /var/ossec/bin/wazuh-analysisd -t
docker exec "$NAME" bash -c '(nohup /var/ossec/bin/wazuh-db >/tmp/db.log 2>&1 &); sleep 3; (nohup /var/ossec/bin/wazuh-analysisd >/tmp/ana.log 2>&1 &)'
for _ in $(seq 1 60); do
  docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest && break
  sleep 1
done
sleep 2

winners() {
  docker exec -i "$NAME" /var/ossec/bin/wazuh-logtest 2>&1 < "$1" | awk '
    /^\*\*Phase 1:/ { if (n > 0) print id; n++; id = "-"; in3 = 0; next }
    /^\*\*Phase 3:/ { in3 = 1; next }
    in3 && /^\tid: / { gsub(/[\047\t]/, ""); sub(/^id: /, ""); id = $0; next }
    END { if (n > 0) print id }'
}

if [ $# -eq 0 ]; then
  set --
  for w in "$FX"/*.winners; do set -- "$@" "$(basename "$w" .winners)"; done
fi
for name in "$@"; do
  fixture=$FX/$name.jsonl
  out=$FX/$name.winners
  header=$(grep '^#' "$out" 2>/dev/null || true)
  got=$(winners "$fixture")
  want=$(grep -vc '^#' "$fixture" || true)
  have=$(printf '%s\n' "$got" | grep -c . || true)
  [ "$have" = "$want" ] || { echo "$name: $have winners for $want events; is every line one event?" >&2; exit 1; }
  { [ -n "$header" ] && printf '%s\n' "$header"; printf '%s\n' "$got"; } > "$out"
  echo "wrote $out"
done
