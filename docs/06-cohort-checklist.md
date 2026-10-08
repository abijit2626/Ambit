# Cohort deployment checklist (M0 and M1)

This is the path from a working repository to the M0 and M1 exit criteria in the README
Roadmap: a 5–10 endpoint volunteer cohort, then the Wazuh side proven on a live manager.
**Nothing here has been run on a cohort.** Every step names what it checks, so a step that
passes means something, and a step that cannot be checked says so.

The order is: close the blockers below, prove it on one machine you own, stand up the
manager, roll out to the cohort, then measure each exit criterion with the procedure given
for it.

## Close these first

Each one will otherwise cost the cohort a week to discover.

1. **The SCA policy contradicts the M0 bundle.** `sca/ambit_managed_settings.yml` asserts
   `disableBypassPermissionsMode`, the sandbox keys and `allowManagedDomainsOnly`
   (checks 10002, 10003, 10004). `deploy/claude-code/managed-settings.m0.json` contains none of
   them, deliberately: M0 allows no behavior change. Rule 100270 (level 12) fires on any failing
   check of this policy (given the unconfirmed SCA parent SID below), and 100271 (level 13) when it persists. Deploy both as they stand and
   every cohort endpoint alerts three times per scan from day one, which buries the one D12
   result the M1 criterion needs. The Windows policy has the same problem with check 10002.

   Decide before rollout: (a) ship an M0 policy that asserts only what the M0 bundle sets
   (checks 10001, 10005, 10006, 10007, 10008), keeping the full policy for the enforcement
   milestone; (b) deploy the enforcement keys, which breaks the zero-change criterion; or
   (c) leave 10002–10004 out of the cohort's agent config. (a) is the recommendation. It is not
   built yet.

2. **Nothing supervises `ambitd`.** The repository ships no launchd job, systemd unit or
   Windows service. `scripts/dev-local.sh` starts it with `nohup` under the user's own settings,
   which is right for one machine and wrong for a cohort: a reboot or a crash leaves the
   endpoint unobserved, and SCA check 10007 then reports D7. Something that starts it at boot
   or login and restarts it has to come from your MDM. Decide what, and where its stderr goes:
   the latency measurement below reads that log.

3. **Hook latency is not reported as a number.** `ambitd` logs `hook response exceeded latency
   budget` for each response slower than `latency_budget_ms` (default 5) and records nothing
   else. A p99 under 5 ms is the same claim as fewer than 1% of responses over budget, so count
   those warnings; the procedure is under M0 below. The timing is inside the handler, so it
   excludes the client's connection time.

4. **The loss counter is narrower than "event loss".** `dropped_events` counts events refused
   because the sink queue was full. It does not count events lost while `ambitd` was down, or
   rotated files deleted at the retention cap. The M0 loss criterion is measured with that
   caveat, and the gaps are visible a different way (D7, rule 100313).

5. **Fingerprint keys are per endpoint unless you provision them.** `ambitd` creates its key if
   none exists at `fingerprint_key_path`. M0 and M1 only compare digests within one endpoint,
   so this works, but it is not the "per-org key" the config comment describes. If you want one
   org key, deliver it before the first start.

6. **Three Wazuh behaviors are unconfirmed and fail silently** (syscheck parent SIDs, the SCA
   parent SID, and how a `<field>` regex matches an array). The Windows agent adds four more.
   `deploy/wazuh/README.md` lists them. Step 3 of "Stand up the manager" confirms them; do not
   skip it, because a wrong one looks exactly like a quiet fleet.

## Prove it on one machine you own

1. `make check && make smoke`. For Windows endpoints, `make smoke-windows` and
   `scripts/smoke.ps1`.
2. `./scripts/dev-local.sh`, then use Claude Code normally for a few days.
   `./scripts/dev-local.sh --status` reports the interesting fraction. If it is far from the
   design's 2–5%, the filter criteria in docs/04 need to tighten before anyone else is asked.
3. Read `events.jsonl` as an analyst would. If anything in it is something you would not want a
   monitoring firm to hold, fix the redaction first.
4. `./scripts/runbook-rehearsal.sh -o <new dir> -r D4` and work one alert yourself, using only the
   analyst directory. Anything you cannot do is a runbook defect.

## Stand up the manager

1. Wazuh **4.x**. 5.x is not supported (`deploy/wazuh/README.md` says why).
2. Copy the rules and restart. A duplicate rule id stops the manager from starting, so check it
   came back:

   ```sh
   sudo cp deploy/wazuh/rules/ambit_*.xml /var/ossec/etc/rules/
   sudo systemctl restart wazuh-manager
   sudo grep -iE "rules|error" /var/ossec/logs/ossec.log | tail -20
   ```

3. Run every fixture through the real engine and compare with the offline expectations:

   ```sh
   while read -r line; do echo "$line" | /var/ossec/bin/wazuh-logtest -q; done \
     < deploy/wazuh/fixtures/events.sample.jsonl
   ```

   Check that `json` is the matched decoder, that the D4/D5 rules named in
   `deploy/wazuh/README.md` fire (100231, 100232, 100234, 100236, 100237, 100239, 100241–100246),
   and that no D5 rule fires on the findings-free drift. Rules 100241–100247 match array
   contents with unanchored literals; if none of them fires, the array-matching assumption is
   what failed, and the fix is in the rules.
4. Set the disconnection timing so rule 504 is useful:
   `agents_disconnection_time` 15m, `agents_disconnection_alert_time` 5m.
5. Confirm archiving is off (`logall` and `logall_json` both `no`).
6. Put the agent group in place: `ossec-localfile.xml` (events only, never `trajectory.jsonl`),
   `ossec-syscheck.xml`, and the SCA policy chosen under blocker 1.

## Roll out to the cohort

Per endpoint, in this order. Ask for 5–10 volunteers who have been told what is collected.

1. Create the data directory private to the account that runs `ambitd`: `0700` on Unix, a
   restricted ACL on Windows (`ambitd` refuses a directory that other accounts can read or that another account owns).
2. Install `ambitd` and `mcp-interpose` from `make cross` and start `ambitd` under whatever you
   chose in blocker 2. `ambitd -print-config` shows the effective configuration; set
   `trusted_repo_paths`, `trusted_content_domains` and, if you classify MCP servers or tools,
   `trusted_mcp_servers` and `mcp_tool_labels`. An unset trusted-repo list makes D8 mostly
   noise early on, as its runbook says.
3. Deliver `deploy/claude-code/managed-settings.m0.json` by MDM. Confirm it with `curl
   http://127.0.0.1:7777/healthz` on the endpoint (`{"status":"ok"}`), then run one Claude Code
   session and check that `events.jsonl` has a `session_start`.
4. For each MCP server the volunteer uses, wrap its command in `mcp-interpose -server NAME`
   in the MCP configuration (the README's "Classifying MCP servers and tools" section shows the
   shape), run a session so the surface is recorded, review it with `-show`,
   and approve it with `-approve`. Do not approve a surface you have not read.
5. Install the Wazuh agent blocks and restart the agent. On Windows follow the "Windows agents"
   section of `deploy/wazuh/README.md`; the wildcard expansion and rotation behaviors there are
   unverified.
6. On the manager, confirm the agent is reporting and that an event from the endpoint decodes.

## M0 exit criteria

| Criterion | How to measure it | Passes when |
| --- | --- | --- |
| 5–10 endpoint volunteer cohort | Wazuh agent list for the group | 5–10 agents active and sending events |
| p99 hook response under 5 ms | Count `hook response exceeded latency budget` in each `ambitd` log, divide by that endpoint's hook-sourced events in `trajectory.jsonl` | Under 1% over budget, on every endpoint. Look at the `took` values too: a few at 4 ms and none at 200 ms is a different result from the reverse |
| Zero developer-visible behavior change | Ask each volunteer: did a prompt appear or disappear, did anything run slower, did any tool call fail that would not have? Also diff their `permissions` and `sandbox` settings against before | Every answer is no, and the managed bundle changed nothing but `env` and `hooks` |
| Spool event loss under 0.1% | Last `health_dropped_events` per endpoint in `events.jsonl`, over that endpoint's total events; add the `sink_gap` markers (rule 100313) | Under 0.1%. State the blocker-4 caveat next to the number |
| Interesting fraction measured | `AMBIT_DIR=<data dir> ./scripts/dev-local.sh --status` on each endpoint (the process line keys on `$AMBIT_DIR/ambitd`; ignore it if the binary is elsewhere) | A number exists. It is not a pass/fail: if it is far from 2–5%, tighten the filter before M1 |
| No `Too many fields for JSON decoder` | `sudo grep -i "too many fields" /var/ossec/logs/ossec.log` | No matches |

## M1 exit criteria

| Criterion | How to exercise it | Expect |
| --- | --- | --- |
| Every MCP server the cohort uses has an approved baseline | `mcp-interpose -server NAME -show` for each server, on each endpoint | Every one says approved |
| A deliberately mutated server triggers D4 within a session | On a test endpoint, change an approved server's tool description (a test server you control, not a vendor's), start a session | Rule 100234 (level 12) in the same session, or 100237 if the server announced the change |
| Killing `ambitd` fires D7 | Stop the daemon, leave the agent running | Rule 100314 via SCA check 10007, within the SCA scan interval |
| Stopping the Wazuh agent fires rule 504 | Stop the agent | Rule 504 after `agents_disconnection_alert_time` |
| Reverting a managed-settings key fires D12 | Edit a key the deployed SCA policy asserts, for example the hook URL (check 10005) | Rule 100270. This is only observable once blocker 1 is closed |
| Someone outside the team executes a runbook against a sample alert | `./scripts/runbook-rehearsal.sh -o <new dir>`, hand over `analyst/` only, collect `FEEDBACK.md` | They reach a decision using only the alert and the runbook, with no question to the team |

For the last row, the packet alerts are built offline. For a rehearsal that counts, produce the
alert on the manager instead: feed the packet's `full_log` line to `wazuh-logtest`, and give the
analyst what the manager actually reports. D11 and D12 have no offline packet (the manifest says
why); for those, cause the condition on a test endpoint and use the real alert. Score against
`answer-key/`, and count every question the analyst asked as a defect in the runbook.

## Rollback

`./scripts/dev-local.sh --uninstall` (and the `.ps1`) removes a user-scope install. For a managed
one, remove the managed-settings bundle and stop `ambitd` as a pair. Either alone trips an alert
on the endpoint: a missing bundle fails SCA check 10001 (D12), and a stopped daemon fails 10007
(D7). So take the endpoint out of the Wazuh agent group, or tell whoever watches the manager,
before you remove anything. Otherwise the alerts that follow are your own.
