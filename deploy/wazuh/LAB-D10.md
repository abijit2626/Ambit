# Lab test plan: D10 on the live manager

This checks the D10 change on the real lab manager and a real endpoint. The offline replays
under `wazuh-logtest` cover the rules; this covers what replay cannot: the live `log_alert_level`,
the live windows, and the path from ambitd through the agent to the manager.

Work through it in order. Each step says what to expect and what would count as a failure. Record
the outcome of every step in `deploy/wazuh/LAB-D10-results.md` (create it), including the steps you
skipped and why.

## What you need

- The lab manager (Wazuh 4.14.8 or a later 4.14.x), with root access on it.
- The lab endpoint running the `ambitd` build from the merge commit `993353b` or later. An older
  build sends no `fp_sighting`, so it is outside this test; see step 6.
- A way to post hook events to ambitd on the endpoint. The hook listens on `hook_addr`, which
  defaults to `127.0.0.1:7777`.

## 1. Read the manager's log alert level

On the manager:

```sh
grep -n 'log_alert_level' /var/ossec/etc/ossec.conf
```

- **Expected:** `3`, the default. Rule 100280 is level 1, so its matches are counted by 100281 and
  100282 but are not written to alerts. This is what the offline runs assume.
- **If it is 1 or 2:** every session's first sighting is written to alerts as 100280. That is noise,
  not a failure, but it changes what you see in step 3. Record the value and continue.

## 2. Load the merged rules and check they parse

On the manager, copy the rules from the merge commit (`deploy/wazuh/rules/ambit_*.xml`) to
`/var/ossec/etc/rules/`, then:

```sh
chown root:wazuh /var/ossec/etc/rules/ambit_*.xml
chmod 660 /var/ossec/etc/rules/ambit_*.xml
/var/ossec/bin/wazuh-analysisd -t
```

- **Expected:** no error other than `Could not set resource limit for file descriptors`, which the
  offline runs also print. Any other error is a failure: stop and send the output.
- Restart the manager (`systemctl restart wazuh-manager`), then confirm the rule loads with one
  event from the offline fixture:

```sh
/var/ossec/bin/wazuh-logtest <<'EOF'
{"schema_v":2,"kind":"fp_sighting","session_id":"lab_probe_1","prov_fp_notable":"hmac:lab-probe","prov_fp_role":"ingest","src":"ambitd"}
EOF
```

- **Expected:** a `Phase 3` line naming rule `100280`, with `level 1`. Its alert is `no` under the
  default level.

## 3. Two sessions, one fingerprint: the tripwire fires once

On the endpoint, post two sessions to ambitd. Use an address no other test uses, so the
fingerprint is unique to this run:

```sh
probe='lab-d10-probe-2026@example.test'
for sid in lab_s1 lab_s2; do
  curl -sS -X POST -H 'Content-Type: application/json' http://127.0.0.1:7777/hook -d "{
    \"hook_event_name\": \"PostToolUse\", \"session_id\": \"$sid\", \"cwd\": \"/home/dev/src/myrepo\",
    \"tool_name\": \"WebFetch\", \"tool_use_id\": \"t_$sid\",
    \"tool_input\": {\"url\": \"https://docs.example.test/contact\"},
    \"tool_response\": \"Contact $probe for access\"}"
  sleep 2
done
```

On the endpoint, the spool and the SIEM sink should now hold:

- `tool_post` events from both sessions, each with the same `prov_fp_notable`.
- one `fp_sighting` for `lab_s1` and one for `lab_s2`, with that same `prov_fp_notable`.

On the manager, check `alerts.json` (or the Wazuh dashboard) for rule `100281`:

- **Expected:** one `100281` alert, about 2 seconds after the second sighting, with
  `session_id` and `prov_fp_notable` set.
- **Failure:** no `100281` (the `fp_sighting` never arrived, or 100280 did not match it), or a
  `100281` that appears before the second session.

## 4. A repeat in the first session does not raise a new alert

Repeat the first session with the same content:

```sh
curl -sS -X POST -H 'Content-Type: application/json' http://127.0.0.1:7777/hook -d "{
  \"hook_event_name\": \"PostToolUse\", \"session_id\": \"lab_s1\", \"cwd\": \"/home/dev/src/myrepo\",
  \"tool_name\": \"WebFetch\", \"tool_use_id\": \"t_lab_s1_repeat\",
  \"tool_input\": {\"url\": \"https://docs.example.test/contact\"},
  \"tool_response\": \"Contact $probe for access\"}"
```

- **Expected:** no new `fp_sighting` for `lab_s1` (check the endpoint's events), and no new
  `100281` on the manager. The `tool_post` itself still carries `prov_fp_notable`.
- **Failure:** a second `fp_sighting` for `lab_s1`, or a second `100281`.

## 5. Windows: the shipped 3600 s and 7200 s values

The 60-second copy in the offline replay showed that the expiry logic works on real time. The
shipped values are not exercised by that replay, so check them here:

- **Expire test (3600 s):** post `lab_s1` again with new content, wait more than 3600 s, then post
  `lab_s2` with the same content. **Expected:** no new `100281`, because the first sighting has
  expired. Then post `lab_s3`, within 3600 s of `lab_s2`. **Expected:** `100281` on `lab_s3`.
- This takes an hour. If you skip it, record the skip. The shipped constants stay untested until
  it is run.

## 6. An older endpoint build

Run one session on a build older than `fp_sighting` (before the merge commit `993353b`). Post
the same content from it.

- **Expected:** no `fp_sighting` event and no `100280`, `100281` or `100282` alert from that
  endpoint. The `tool_post` still arrives with `prov_fp_notable`, but D10 does not count it.
- This is the known gap, recorded in the D10 runbook. A mismatch here means the gap is wider than
  documented.

## 7. Rule 100271 on two agents (D12)

This is not D10, but it rests on the same finding and cannot be replayed offline. 100271 used to
carry `ignore="7200"`, which would have let one agent's alert silence every other agent's for two
hours. The ignore is removed, and only a real SCA path can show the effect. You need two agents
whose managed-settings check (policy `ambit_managed_settings`) fails.

- Make the check fail three times on agent 1 inside two hours, then three times on agent 2.
- **Expected:** one `100271` for each agent, with that agent's `agent.name`. Without the fix, agent
  2's alert would be missing.
- **Failure:** `100271` for agent 1 only. Send the `alerts.json` lines for both agents.

## 8. Clean up

- Remove the probe events from the lab's Wazuh data if your retention policy requires it.
- Record the results file, including the `log_alert_level` value from step 1, the `wazuh-analysisd -t`
  output from step 2, and each step's outcome.
