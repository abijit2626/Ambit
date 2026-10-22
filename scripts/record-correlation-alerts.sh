#!/usr/bin/env bash
# Replays deploy/wazuh/fixtures/g-two-keys.jsonl and g-flood.jsonl through a fresh wazuh-manager 4.14.8
# container (one wazuh-logtest process per file, so correlation state is shared across the file) and
# writes g-two-keys.alerts and g-flood.alerts: one line per event, "N rule level=L alert=yes|no".
# alert=no with a rule id means the rule matched and was suppressed (what `ignore` does).
# Needs docker and network access to pull the image. Regenerate the fixtures first with
# scripts/gen-correlation-fixtures.sh if the manifest changes.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FX=$ROOT/deploy/wazuh/fixtures
RULES=${RULES:-$ROOT/deploy/wazuh/rules}
NAME=ambit-record-correlation-$$
IMAGE=wazuh/wazuh-manager:4.14.8

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

replay() {
  docker exec -i "$NAME" /var/ossec/bin/wazuh-logtest 2>&1 < "$1" | awk '
    /^\*\*Phase 1:/ { if (n > 0) emit(); n++; id = "none"; lvl = "-"; alert = "no"; in3 = 0; next }
    /^\*\*Phase 3:/ { in3 = 1; next }
    in3 && /^\tid: / { gsub(/[\047\t]/, ""); sub(/^id: /, ""); id = $0; next }
    in3 && /^\tlevel: / { gsub(/[\047\t]/, ""); sub(/^level: /, ""); lvl = $0; next }
    /^\*\*Alert to be generated/ { alert = "yes"; in3 = 0; next }
    function emit() { printf "%d %s level=%s alert=%s\n", n, id, lvl, alert }
    END { if (n > 0) emit() }'
}

for name in g-two-keys g-flood; do
  {
    echo "# Recorded with wazuh-logtest on $IMAGE by scripts/record-correlation-alerts.sh: one logtest process"
    echo "# fed $name.jsonl, one event per line. Columns: line, rule that matched, its level, whether it alerted."
    echo "# alert=no next to a rule id means the rule matched and was suppressed."
    replay "$FX/$name.jsonl"
  } > "$FX/$name.alerts"
  echo "wrote $FX/$name.alerts"
done
