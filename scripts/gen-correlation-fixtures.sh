#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FX=${FX:-$ROOT/deploy/wazuh/fixtures}
TWO=$FX/g-two-keys.jsonl
FLOOD=$FX/g-flood.jsonl
MANIFEST=$FX/g-correlation.tsv
D10=$FX/g-d10.jsonl
D10_MANIFEST=$FX/g-d10.tsv

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

# D10 (100281, 100282) is not "one key sent N times": 100281 needs the same fingerprint in two different
# sessions, and 100282 counts 100281's alerts. Each scenario below is replayed in its own logtest process
# (scripts/record-correlation-alerts.sh reads the line ranges from g-d10.tsv). The rules count fp_sighting
# events, so every scenario is built from the fp_sighting in events.sample.jsonl, varying only
# prov_fp_notable, session_id, event_id and sequence; the last two scenarios also use its tool_post.
d10_tpl=$(jq -c 'select(.kind=="fp_sighting")' "$FX/events.sample.jsonl" | sed -n 1p)
[ -n "$d10_tpl" ] || { echo "no fp_sighting in events.sample.jsonl" >&2; exit 1; }
post_tpl=$(jq -c 'select(.kind=="tool_post" and .prov_fp_notable!=null)' "$FX/events.sample.jsonl" | sed -n 1p)
[ -n "$post_tpl" ] || { echo "no tool_post with prov_fp_notable in events.sample.jsonl" >&2; exit 1; }
FP_X=$(jq -r .prov_fp_notable <<<"$d10_tpl")
FP_Y=hmac:d10_other_fingerprint
FP_Z=hmac:d10_third_fingerprint
COLLIDE='.tool_name="Bash" | .bash_argv0="curl" | .bash_command_class="network" | .secret_hit_kinds=["aws_access_key_id"]'

: > "$D10"
printf 'scenario\tfirst\tlast\tdescription\n' > "$D10_MANIFEST"
d10_n=0

# d10_event <template> <scenario> <index> <session> <fingerprint> <extra jq filter, or .>
d10_event() {
  jq -c --arg s "$4" --arg f "$5" --arg n "$2" --argjson i "$3" \
    "(.session_id=\$s | .prov_fp_notable=\$f | .event_id=(\"d10_\"+\$n+\"_\"+(\$i|tostring)) | .sequence=\$i) | ($6)" <<<"$1" >> "$D10"
  d10_n=$((d10_n + 1))
}

# d10 <scenario> <description> <session[:fingerprint]>...: one fp_sighting per argument
d10() {
  local name=$1 desc=$2
  shift 2
  local first=$((d10_n + 1)) i=0 spec fp
  for spec in "$@"; do
    i=$((i + 1))
    fp=$FP_X
    case "$spec" in *:*) fp=${spec#*:} ;; esac
    d10_event "$d10_tpl" "$name" "$i" "${spec%%:*}" "$fp" .
  done
  printf '%s\t%s\t%s\t%s\n' "$name" "$first" "$d10_n" "$desc" >> "$D10_MANIFEST"
}
rep() { local k; for k in $(seq 1 "$2"); do printf '%s ' "$1"; done; }

d10 one-session-x12      "one session repeats a fingerprint 12 times" $(rep A 12)
d10 twelve-sessions      "12 different sessions each see it once" $(printf 'S%s ' $(seq 1 12))
d10 a-once-then-b-x20    "session A once, then session B 20 times (ambitd without emit-once)" A $(rep B 20)
d10 a-x20-then-b-once    "session A 20 times, then session B once (ambitd without emit-once)" $(rep A 20) B
d10 emit-once-a-then-b   "what ambitd emits for the two scenarios above with emit-once: A once, B once" A B
d10 two-fingerprints     "two fingerprints, each seen in sessions A then B: each must alert on its own" A:$FP_X A:$FP_Y B:$FP_X B:$FP_Y
d10 unrelated-fingerprints "three sessions, each sees a different fingerprint: same_field must keep these apart" A:$FP_X B:$FP_Y C:$FP_Z

# What ambitd sends for 12 sessions: each tool_post, then its fp_sighting. The even-numbered tool_posts also
# match 100302 (secret in a network command): they must still alert as 100302, and D10 must still count all
# twelve sightings, because the sighting is a separate event nothing else competes for.
first=$((d10_n + 1))
for i in $(seq 1 12); do
  extra=. sighting=.
  [ $((i % 2)) -eq 0 ] && extra=$COLLIDE sighting='.tool_name="Bash"' # a sighting names the tool its post came from
  d10_event "$post_tpl" collision-100302-post "$i" "S$i" "$FP_X" "$extra"
  d10_event "$d10_tpl" collision-100302-sighting "$i" "S$i" "$FP_X" "$sighting"
done
printf '%s\t%s\t%s\t%s\n' collision-100302-alternate "$first" "$d10_n" "12 sessions, each a tool_post then its fp_sighting; the even-numbered tool_posts also match 100302" >> "$D10_MANIFEST"

# An ambitd build older than fp_sighting puts the fingerprint only on the tool_post: not counted any more.
first=$((d10_n + 1))
for i in $(seq 1 12); do d10_event "$post_tpl" tool-post-only "$i" "S$i" "$FP_X" .; done
printf '%s\t%s\t%s\t%s\n' tool-post-only "$first" "$d10_n" "12 sessions whose ambitd puts the fingerprint only on the tool_post (older builds): D10 does not count these" >> "$D10_MANIFEST"

echo "wrote $D10 ($d10_n lines), $D10_MANIFEST"
