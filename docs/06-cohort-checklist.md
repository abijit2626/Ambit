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

1. **Deploy the M0 SCA policy, not the full one.** `sca/ambit_managed_settings.yml` asserts
   `disableBypassPermissionsMode`, the sandbox keys and `allowManagedDomainsOnly` (checks 10002,
   10003, 10004). `deploy/claude-code/managed-settings.m0.json` contains none of them,
   deliberately: M0 allows no behavior change. Rule 100270 (level 12) fires on any failing check
   of the policy (given the unconfirmed SCA parent SID below), and 100271 (level 13) when it
   persists, so the full policy against the M0 bundle alerts three times per scan on every
   endpoint from day one. The Windows policy has the same problem with check 10002.

   The fix is in the repository: `sca/ambit_managed_settings_m0.yml` and
   `sca/ambit_managed_settings_windows_m0.yml` keep the checks the M0 bundle satisfies (10001,
   10005, 10006, 10007, 10008) and drop the rest. They share the policy id and check ids, so no
   manager rule changes. Deploy exactly one policy file per agent, and move to the full one only
   when the enforcement keys ship in managed settings. `deploy/wazuh/sca_test.go` keeps the M0
   files verbatim subsets, checks each against the M0 bundle, and fails if the bundle gains a
   key that makes the full policy pass.

2. **Install `ambitd` as a system service, not with `dev-local`.** `scripts/dev-local.sh` starts
   it with `nohup` under the user's own settings, which is right for one machine and wrong for a
   cohort: a reboot or a crash leaves the endpoint unobserved. `scripts/install-system.sh` (Linux,
   macOS) and `scripts/install-system.ps1` (Windows) install it the way a monitoring agent runs:
   as root or SYSTEM, from boot, with the service manager set to bring it back if it exits. On
   Linux that is the unit's `Restart=always` and on macOS the LaunchDaemon's `KeepAlive`; neither
   has been observed to fire. On Windows the task's own restart-on-failure setting did not restart
   `ambitd` on a test machine, so the installer registers a repeating one-minute trigger with
   `MultipleInstances` set to `IgnoreNew`, and checks that it is there after registering. The
   definitions are in `deploy/service/`: a systemd unit, a LaunchDaemon, and on Windows a
   scheduled task, because `ambitd` is a console program and making it a Windows service would
   add a dependency. The
   installer starts the service and checks its health before it installs the managed settings,
   and refuses to overwrite managed settings that are not the M0 bundle. Logs: `journalctl -u
   ambitd` on Linux, `/Library/Logs/ambit/ambitd.log` on macOS,
   `C:\ProgramData\ambit\ambitd.log` on Windows. They name each slow hook response; the
   measurement itself comes from `ambitd report` (blocker 3).

   As a system service, `ambitd`'s own home directory is root's or SYSTEM's, not the
   developer's. It takes each session's home from the transcript path Claude Code reports
   instead, so developer files outside the working directory keep their `home` zone. A session
   whose transcript lives elsewhere (`CLAUDE_CONFIG_DIR`) falls back to the service account's
   home; set `home` in the config for those.

   What is verified: the Linux installer's whole flow (install, upgrade, status, uninstall,
   refusing a held port and existing managed settings), run against a stub service manager and a
   real `ambitd`; and the systemd unit, with `systemd-analyze verify`. The Windows installer has
   run on one machine, where the repeating trigger brought `ambitd` back about 55 seconds after a
   kill when it was added by hand, and where an upgrade with that trigger in place failed because
   the daemon restarted between the stop and the binary copy; the installer now disables the task
   first, and that change is not yet run on a real machine. What is not verified: the restart on
   Linux or macOS, and the macOS installer. Kill `ambitd` on a test machine of each kind and
   watch it come back before rolling out.

3. **Hook latency is measured inside the handler, in buckets.** `ambitd` times every `/hook`
   response and keeps a histogram (bucket bounds from 250 µs to 1 s, 5 ms among them), the count
   over `latency_budget_ms` (default 5), and the maximum. The counters ride on every
   `ambitd_health` event in the spool as `hook_latency`; they do not cross to Wazuh. `ambitd
   report` merges every run in the spool and prints p50, p95 and p99. A quantile is the upper
   bound of its bucket, so read "p99 ≤ 5.0ms", not "p99 = 5.0ms". The pass/fail line does not
   depend on the buckets: a p99 under 5 ms is the same claim as fewer than 1% of responses over
   budget, and that count is exact. The timing starts when the handler is entered, so it excludes
   the client's connection time. `ambitd` still logs `hook response exceeded latency budget` for
   each slow response, which says when they happened.

4. **"Event loss" counts what ambitd saw and failed to keep.** `ambitd report` adds three
   counters per run: events refused because the sink queue was full (`dropped_events`), lines a
   sink failed to write (`write_errors`), and hook requests ambitd could not read or parse
   (`parse_errors`), over the lines the spool did write. An unparseable body also sets the health
   status to `degraded`. Two things are reported beside the number rather than in it, because
   ambitd cannot count events it never received:
   - **Downtime.** `ambitd.state`, next to the spool, records each run's last heartbeat and
     whether it stopped cleanly. The next run reports the previous one as `clean`, `unclean` or
     `unknown` with the seconds it was down (an upper bound for an unclean stop, measured from the
     last heartbeat). Hook calls Claude Code made in that window are lost and uncounted.
   - **Retention.** The report warns when the spool has deleted files at its size cap. Every
     counter is cumulative for its run, so a run is lost to the report only when all its health
     events have been deleted; the warning says the window may be missing older runs.

   A clean stop is a SIGTERM or Ctrl-C, which is how systemd and launchd stop a service. On
   Windows, `Stop-ScheduledTask`, the installer and a reboot end `ambitd` by terminating the
   process, which leaves it no chance to write a final event, so expect Windows runs to end
   `unclean` (inferred from how the task is stopped; not yet observed). Read the downtime there,
   not the stop kind.

5. **Fingerprint keys are per endpoint unless you provision them.** `ambitd` creates its key if
   none exists at `fingerprint_key_path`. M0 and M1 only compare digests within one endpoint,
   so this works, but each endpoint then has its own key rather than one for the org. If you want
   one org key, deliver it before the first start.

6. **Three Wazuh behaviors are unconfirmed and fail silently** (syscheck parent SIDs, the SCA
   parent SID, and how a `<field>` regex matches an array). The Windows agent adds four more.
   `deploy/wazuh/README.md` lists them. Step 3 of "Stand up the manager" confirms them; do not
   skip it, because a wrong one looks exactly like a quiet fleet.

7. **A volunteer with the sandbox on sends ambitd nothing over http unless `127.0.0.1` is an
   allowed domain.** With `sandbox.enabled`, Claude Code posts every `http` hook through the
   sandbox's network proxy, and the proxy answers a host that is not in
   `sandbox.network.allowedDomains` with a 403 (observed on v2.1.310 under `claude -p`: every
   http hook failed with "HTTP 403", and ambitd saw only the `session_start` from the command
   hook). Adding `"127.0.0.1"` to `allowedDomains` made every hook arrive. Whether an
   interactive session prompts the developer for it instead of failing is not observed.
   **Resolved for managed endpoints:** the M0 bundle now carries `"127.0.0.1"` in
   `sandbox.network.allowedDomains`, so a volunteer who installs it through
   `install-system` needs nothing more. The bundle does not turn the sandbox on, so a
   volunteer who runs without it is unaffected either way. Still open for anyone set up another
   way (`dev-local`, or settings delivered without the bundle): `ambitd doctor` fails when the
   sandbox is on without the entry, and `ambitd report` warns when sessions send nothing after
   their `SessionStart`, which is this failure's signature. Allowing `127.0.0.1` lets sandboxed
   commands reach every local port, ambitd's included; docs/02 has the trade-off, and the owner
   accepted it when adopting the bundle entry.

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

3. Run every fixture through the real engine and compare with the offline expectations. Use the
   loop under "Verify the D4/D5 rules" in `deploy/wazuh/README.md`, which prints one line per
   fixture: the decoder, the rule and its level. Do not use `wazuh-logtest -q`: on Wazuh 4.14.8
   it prints nothing for a line that matches, and without it the result goes to stderr, so a
   loop built on `-q` reads as a manager where nothing fires.

   Check that `json` is the matched decoder, that the D4/D5 rules named in
   `deploy/wazuh/README.md` fire (100231, 100232, 100234, 100236, 100237, 100239, 100241–100246),
   and that no D5 rule fires on the findings-free drift. Rules 100241–100247 match array
   contents with unanchored literals; if none of them fires, the array-matching assumption is
   what failed, and the fix is in the rules.
4. Set the disconnection timing so rule 504 is useful:
   `agents_disconnection_time` 15m, `agents_disconnection_alert_time` 5m.
5. Confirm archiving is off (`logall` and `logall_json` both `no`).
6. Put the agent group in place: `ossec-localfile.xml` (events only, never `trajectory.jsonl`),
   `ossec-syscheck.xml`, and the M0 SCA policy (blocker 1).

## Roll out to the cohort

Per endpoint, in this order. Ask for 5–10 volunteers who have been told what is collected.

1. If the volunteer tried `dev-local` first, remove it: `./scripts/dev-local.sh --uninstall`
   (or the `.ps1`). It holds the same port, and the installer refuses to start next to it.
2. Build with `make cross` and run, as root or from an Administrator PowerShell:
   `sudo ./scripts/install-system.sh --binary bin/ambitd-<os>-<arch>`, or
   `.\scripts\install-system.ps1 -Binary .\bin\ambitd-windows-<arch>.exe`. It creates the data
   directory, installs and starts the service, waits for the health endpoint, then installs
   `deploy/claude-code/managed-settings.m0.json`. `--status` (`-Status`) shows the state.
3. Optional configuration goes in `/etc/ambit/config.json`, `/usr/local/etc/ambit/config.json`
   or `C:\ProgramData\ambit\config.json`; restart the service after changing it.
   `ambitd -print-config` shows the effective configuration, and `ambitd doctor -config <config>`,
   run as the volunteer from their project directory, reads the Claude Code settings they will run
   with and fails if a hook points elsewhere, the OTel exporter is not http/json, or the sandbox is
   on without `127.0.0.1` allowed (blocker 7). Set `trusted_repo_paths`,
   `trusted_content_domains` and, if you classify MCP servers or tools, `trusted_mcp_servers` and
   `mcp_tool_labels`. An unset trusted-repo list makes D8 mostly noise early on, as its runbook
   says. Then run one Claude Code session, send one prompt, and check that `events.jsonl` gains a
   `session_start` line and a `prompt_submit` line. `session_start` comes from the bundle's
   `SessionStart` command hook (`ambitd hook-forward`), because Claude Code does not deliver
   that event to an `http` hook; if only `prompt_submit` appears, that hook is not running (see
   the README's known limitations). Its `permission_mode` is empty, by design of the payload.
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
| p99 hook response under 5 ms | `ambitd report` on each endpoint (`sudo ambitd report -config <config>`; `install-system --status` and `dev-local.sh --status` run it too). It merges every run in the spool | The latency line says `[PASS]`: under 1% of responses over budget, on every endpoint. Look at the max and p95 too: a few at 4 ms and none at 200 ms is a different result from the reverse |
| Zero developer-visible behavior change | Ask each volunteer: did a prompt appear or disappear, did anything run slower, did any tool call fail that would not have? Also diff their `permissions` and `sandbox` settings against before | Every answer is no, and the managed bundle changed nothing but `env`, `hooks`, and the one `sandbox.network.allowedDomains` entry for `127.0.0.1`, which does not turn the sandbox on but does let a sandboxed command reach local ports |
| Spool event loss under 0.1% | `ambitd report`, the loss line. Cross-check against the `sink_gap` markers (rule 100313) on the manager | The loss line says `[PASS]`. State the restarts line next to it (blocker 4): downtime is loss the counter cannot see |
| Interesting fraction measured | `ambitd report`, the interesting-fraction line: hook tool events that crossed, over all hook tool events | A number exists. It is not a pass/fail: if it is far from 2–5%, tighten the filter before M1 |
| No `Too many fields for JSON decoder` | `sudo grep -i "too many fields" /var/ossec/logs/ossec.log` | No matches |

## M1 exit criteria

| Criterion | How to exercise it | Expect |
| --- | --- | --- |
| Every MCP server the cohort uses has an approved baseline | `mcp-interpose -server NAME -show` for each server, on each endpoint | Every one says approved |
| A deliberately mutated server triggers D4 within a session | On a test endpoint, change an approved server's tool description (a test server you control, not a vendor's), start a session | Rule 100234 (level 12) in the same session, or 100237 if the server announced the change |
| Killing `ambitd` fires D7 | Stop the daemon, leave the agent running | Rule 100314 via SCA check 10007, within the SCA scan interval |
| Stopping the Wazuh agent fires rule 504 | Stop the agent | Rule 504 after `agents_disconnection_alert_time` |
| Reverting a managed-settings key fires D12 | Edit a key the deployed SCA policy asserts, for example the hook URL (check 10005) | Rule 100270. Use the M0 policy (blocker 1): against the full one, this result would be buried in permanent failures |
| Someone outside the team executes a runbook against a sample alert | `./scripts/runbook-rehearsal.sh -o <new dir>`, hand over `analyst/` only, collect `FEEDBACK.md` | They reach a decision using only the alert and the runbook, with no question to the team |

For the last row, the packet alerts are built offline. For a rehearsal that counts, produce the
alert on the manager instead: feed the packet's `full_log` line to `wazuh-logtest`, and give the
analyst what the manager actually reports. D11 and D12 have no offline packet (the manifest says
why); for those, cause the condition on a test endpoint and use the real alert. Score against
`answer-key/`, and count every question the analyst asked as a defect in the runbook.

## Rollback

`sudo ./scripts/install-system.sh --uninstall` (`.\scripts\install-system.ps1 -Uninstall`)
removes the managed settings first, if they are the M0 bundle, then the service and the binary.
It keeps the spool and the fingerprint key; `--purge` (`-Purge`) removes them too.
`./scripts/dev-local.sh --uninstall` removes a user-scope install.

Removing either half trips an alert on the endpoint: a missing bundle fails SCA check 10001
(D12), and a stopped daemon fails 10007 (D7). So take the endpoint out of the Wazuh agent group,
or tell whoever watches the manager, before you remove anything. Otherwise the alerts that follow
are your own.
