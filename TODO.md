# To do

What is left between the repository as it stands and the M0 and M1 exit criteria. It points at
the documents that hold the detail rather than repeating them: the Roadmap and Known
limitations in the [README](README.md), and the [cohort checklist](docs/06-cohort-checklist.md).
Nothing below has been run on a cohort. Tick a box when you have seen the result yourself,
and say where in the item.

## 1. Verify what is built but untested

- [ ] Linux restart: `sudo ./scripts/verify-restart.sh` on a test machine under the installed
      systemd unit. The script is tested against a shell loop, not against systemd.
- [ ] macOS restart, and the macOS installer end to end. Neither has run on a real Mac.
- [ ] Windows: the installer's new `ambitd stop` path, which has only run under PowerShell 7 on
      Linux.
- [ ] Windows: a fresh data directory and a reboot, and which mechanism restarts `ambitd`.
- [ ] A live session's `SessionStart` reaching `ambitd` through the bundle's `hook-forward`
      command, and rule 100200 firing from a live `session_mode` event.
- [ ] Whether an interactive session prompts for `127.0.0.1` when the sandbox is on
      (checklist, blocker 7).

## 2. Prove the Wazuh side on a live manager

- [ ] The three silent-failure behaviors: syscheck parent SIDs, the SCA parent SID, and how a
      `<field>` regex matches an array.
- [ ] Every fixture through `wazuh-logtest`: `sudo ./scripts/verify-manager.sh` on the manager
      (tested against a stand-in, never against a real engine). Not `-q`.
- [ ] Windows agent: FIM wildcard expansion, log rotation under `log_format json`, SCA `f:` and
      `c:` rules, and `whodata`.
- [ ] `agents_disconnection_time` 15m, `agents_disconnection_alert_time` 5m, archiving off.

## 3. M0: run the cohort

- [ ] Your own machine first: `make check && make smoke`, a few days on `dev-local`, then read
      `events.jsonl` as an analyst would.
- [ ] 5-10 volunteers who have been told what is collected.
- [ ] The M0 SCA policy on each agent, never the full one.
- [ ] Decide whether the org wants one fingerprint key, before the first start.
- [ ] p99 hook response under 5 ms, from `ambitd report` on each endpoint.
- [ ] Spool event loss under 0.1%, with the restarts line stated beside it.
- [ ] The interesting fraction measured against the 2-5% estimate.
- [ ] No `Too many fields for JSON decoder` in the manager log.
- [ ] Zero developer-visible change, by asking each volunteer.

## 4. M1: exercise the detectors

Start `sudo ./scripts/expect-alert.sh --rule N --agent NAME` on the manager before causing each
condition below. It has only been tested on lines written to `alerts.json`'s documented layout.

- [ ] Every MCP server the cohort uses wrapped in `mcp-interpose`, reviewed and approved.
- [ ] A mutated test server fires D4 (100234) in the same session.
- [ ] Killing `ambitd` fires D7 (100314); stopping the Wazuh agent fires rule 504.
- [ ] Reverting a managed-settings key fires D12 (100270).
- [ ] Someone outside the team works a runbook from a real manager alert.

## 5. Build work

- [ ] M4 goal drift against the real Messages API on an endpoint. Today it has only run against a
      stand-in.
- [ ] M2: precision on a real developer cohort, and a decision on Rule-of-Two scoping across
      `/clear` and long sessions.
- [ ] An emitter for `agent_entrypoint` (rule 100204 is inert). It needs a real Claude Code
      payload or attribute that carries it, which has not been found.
- [ ] D9 per-endpoint egress destination profiling.
- [ ] Try `mcp-interpose -suggest-labels` on the tool lists the cohort really uses, and tune its
      heuristics from what it gets wrong. The gate does nothing without labels.
- [ ] MCP servers reached over HTTP/SSE; `mcp-interpose` covers stdio only.
- [ ] A chosen and tested tenancy model for third-party monitoring.
- [ ] M3 (enforce) and M5 (fleet correlation) are design only. They wait on evidence from the
      steps above, and enforcement begins at `ask`, not `deny`.
