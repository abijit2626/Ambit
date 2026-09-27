# Runbook D6 — config tamper

**Rules:** 100250–100256 (group `ambit_d6`). **MITRE:** T1562.001, plus T1195.002 for MCP
configuration.

Every control in this system rests on endpoint configuration: the hook that produces the
event stream, the sandbox, the egress allowlist, the managed settings that pin them. Editing
that configuration is the cheapest way to switch the monitoring off, and it produces no
alert unless someone is watching the files.

D6 has two halves and neither is sufficient alone. Claude Code reports configuration changes
it makes or loads; Wazuh's FIM reports what happened on disk, and with `whodata` reports
**which process did it** — the question that matters when malware, not the developer, is
doing the editing.

| Rule | Level | Source | Means |
| --- | --- | --- | --- |
| 100250 | 7 | ambit | Configuration changed in-session |
| 100251 | 7 | ambit | A watched file changed |
| 100252 | 12 | ambit | 3+ configuration changes in one session within 600s |
| 100253 | 13 | ambit | A **system-zone** configuration change |
| 100254 | 13 | FIM | **managed-settings.json modified on disk** |
| 100255 | 12 | FIM | `.mcp.json` modified on disk |
| 100256 | 13 | FIM | The MCP **baseline store** modified |

## What this alert asserts

- **ambit-sourced rules** (100250–100253): Claude Code reported a configuration change.
  `config_source` names which scope (user, project, managed), `config_zone` says whether the
  file sits in the user's home or the system zone. The path is a keyed digest.
- **FIM-sourced rules** (100254–100256): the file changed on disk. Here the path is in
  cleartext, because it comes from Wazuh's own syscheck rather than from our schema, and with
  `whodata` the alert names the process and user that wrote it.
- 100256 asserts something specific and serious: the interposer's approved-baseline store was
  edited. That store is what D4 compares MCP metadata against, so rewriting it makes a rug
  pull read as approved. It is the one way to disable D4 without stopping any process.

## What it does not assert

- **The FIM parent SIDs and field names are unverified.** Rules 100254–100256 chain from
  syscheck rule IDs 550/553/554 and read `file` and `syscheck.audit.*`. Those values were not
  confirmed against the deployed ruleset (`docs/00-sources.md`). A wrong parent does not
  error — the rule silently never fires. If you have never seen one of these alerts on an
  endpoint where settings demonstrably changed, suspect the wiring rather than the endpoint.
- **In-session changes are ordinary.** Developers edit their own settings. 100250 is level 7
  because volume here is expected; the correlation and the system-zone rule are the signals.
- **`whodata` may not be available.** It needs Linux Audit or eBPF. Where it is absent the FIM
  entries still fire but the process attribution is missing, which removes most of their value.
  Check whether it is enabled before concluding a change was unattributed.
- **It does not cover a settings path passed as a command-line flag**, or an in-memory change
  that never touches disk. The ambit half covers some of that; neither half covers all of it.

## Triage

1. **Which half fired?** An ambit-sourced alert with no FIM alert means a change Claude Code
   knows about that did not land in a watched path. A FIM alert with no ambit-sourced alert
   means something edited the file *outside* the agent — which is the adversary-A1 shape.
2. **For FIM alerts, read the writing process.** `syscheck.audit.process.name` is the whole
   question. A package manager, an editor or a configuration-management agent is one story; an
   unexpected interpreter, a shell, or the agent's own binary is another.
3. **For 100253 and 100254, check whether a D12 alert followed.** Managed settings are asserted
   by SCA on a schedule; if the change broke an assertion, D12 fires and tells you which one.
   A managed-settings change with no D12 failure may be a legitimate deployment.
4. **For 100256, go straight to D4.** Pull the baseline file and compare the approved hashes
   against what the servers currently advertise. If the store was rewritten to match a drifted
   surface, D4 has been silenced and every subsequent `approved` verdict from that endpoint is
   worthless.
5. **For 100252, read the sequence.** Repeated changes in minutes is either configuration
   management running or someone iterating until something stops being blocked.

## What requires us

- **Digest resolution** for `config_path_digest` on the ambit-sourced rules, to name the file.
- **The before/after diff.** FIM's `report_changes` carries it for text files; for the ambit
  half the content is not in the event at all.
- **Baseline pull** for 100256: the store's contents, and whether the approval timestamps match
  a real approval run.
- **Confirmation of whether `whodata` is active** on the endpoint.

## Containment

Not automatic, not yours to dispatch.

1. For 100254: restore managed settings from the MDM source rather than editing in place, and
   treat the endpoint as unmonitored for the window between the change and the restore.
2. For 100256: revoke approval for every server on that endpoint
   (`mcp-interpose -server <name> -revoke`) so listings alert again, then re-approve
   deliberately after review. Do not trust the existing baseline.
3. For 100255: review the added or changed MCP server before the next session, and remove it if
   nobody can say who added it.
4. Credential revocation only if the change enabled an action that reached credentials.

## Escalation

**Page** on 100254 and 100256; on 100255 where the writing process is not a known package
manager or editor; and on 100253.

**Queue** 100250, 100251 and 100252.

**Raise the wiring question, not an incident**, if the FIM-sourced rules have never fired on any
endpoint: that is more likely an unverified parent SID than a fleet with immaculate configuration.
