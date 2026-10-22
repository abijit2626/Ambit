#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FX=${FX:-$ROOT/deploy/wazuh/fixtures}
TWO=$FX/g-two-keys.jsonl
FLOOD=$FX/g-flood.jsonl
MANIFEST=$FX/g-correlation.tsv

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

: > "$TWO"
: > "$FLOOD"
printf 'rule\tkey_field\tthreshold\ttwo_first\ttwo_last\tflood_first\tflood_last\tsource\n' > "$MANIFEST"

# rule @ fixture @ jq selector for the template event @ field that keys the correlation @ threshold @ source
SPECS=(
  "100221@events.sample.jsonl@select(.kind==\"permission_denied\")@session_id@5@ambitd"
  "100301@events.sample.jsonl@select(.kind==\"tool_pre\" and .bash_command_class==\"network\" and .permission_mode==\"default\")@session_id@10@ambitd"
  "100252@events.sample.jsonl@select(.kind==\"config_change\")@session_id@3@ambitd"
  "100292@events.sample.jsonl@select(.kind==\"instructions_loaded\" and .config_trusted==false)@session_id@3@ambitd"
  "100240@d5-matrix.jsonl@select(.mcp_baseline_state==\"drift\" and .mcp_scan_classes==[\"role_assertion\"])@tool_mcp_server@3@ambitd"
  "100248@d5-matrix.jsonl@select(.mcp_baseline_state==\"approved\" and ((.mcp_scan_classes // [])|index(\"hidden_instruction\")))@tool_mcp_server@3@ambitd"
  "100312@events.sample.jsonl@select(.kind==\"ambitd_health\" and .health_status==\"degraded\")@endpoint_id@3@ambitd"
  "100281@events.sample.jsonl@select(.kind==\"tool_post\" and .prov_fp_notable!=null)@prov_fp_notable@2@ambitd"
  "100282@events.sample.jsonl@select(.kind==\"tool_post\" and .prov_fp_notable!=null)@prov_fp_notable@5@ambitd"
  "100261@events.sample.jsonl@select(.kind==\"tool_pre\" and .permission_mode==\"default\")@endpoint_id@5@synthetic"
)

two_n=0
flood_n=0
for spec in "${SPECS[@]}"; do
  IFS='@' read -r rule file selector field n source <<<"$spec"
  tpl=$(jq -c "$selector" "$FX/$file" | sed -n 1p)
  [ -n "$tpl" ] || { echo "no template event for rule $rule in $file" >&2; exit 1; }
  extra='.'
  # the default-mode template carries provenance, taint and R2 gate fields; rules 100280, 100283 and 100323
  # would win over the rule under test, so those two rules get a plain network tool_pre
  strip='with_entries(select(.key|test("^(prov_|policy_|r2_)")|not)) | del(.taint_labels)'
  case "$rule" in 100301) extra="$strip" ;; esac
  if [ "$rule" = 100261 ]; then
    # no emitter produces policy_decision=fail_open yet (the rule is marked pending_emitter), so this
    # block is a real tool_pre event with that one field added
    extra="$strip | del(.bash_command_class) | .policy_decision=\"fail_open\""
  fi

  two_first=$((two_n + 1))
  for key in A B; do
    for i in $(seq 1 "$n"); do
      jq -c --arg f "$field" --arg k "g${rule}_${key}" --argjson i "$i" --arg r "$rule" \
        "($extra) | .[\$f]=\$k | .event_id=(\"g\"+\$r+\"_\"+\$k+\"_\"+(\$i|tostring)) | .sequence=\$i" <<<"$tpl" >> "$TWO"
      two_n=$((two_n + 1))
    done
  done

  flood_first=$((flood_n + 1))
  for i in $(seq 1 $((n * 4))); do
    jq -c --arg f "$field" --arg k "g${rule}_F" --argjson i "$i" --arg r "$rule" \
      "($extra) | .[\$f]=\$k | .event_id=(\"g\"+\$r+\"_F_\"+(\$i|tostring)) | .sequence=\$i" <<<"$tpl" >> "$FLOOD"
    flood_n=$((flood_n + 1))
  done

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rule" "$field" "$n" "$two_first" "$two_n" "$flood_first" "$flood_n" "$source" >> "$MANIFEST"
done

echo "wrote $TWO ($two_n lines), $FLOOD ($flood_n lines), $MANIFEST"
