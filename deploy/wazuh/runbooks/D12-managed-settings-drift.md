# Runbook D12 — managed-settings drift

**Rules:** 100270–100271 (group `ambit_d12`). **MITRE:** T1562.001.

Managed settings sit at the highest configuration precedence in Claude Code: no user setting,
project setting or command-line argument overrides a managed permission rule, and managed hooks
cannot be disabled by a lower scope. Every other control in this system rests on that — the hook
that produces the event stream, the sandbox, the egress allowlist, the disabled bypass mode. SCA
turns those from assumptions into checks that run on a schedule.

| Rule | Level | Means |
| --- | --- | --- |
| 100270 | 12 | **An ambit managed-settings assertion failed** |
| 100271 | 13 | The same assertion failing persistently on one endpoint |

While managed settings are observation-only (M0), endpoints run a subset of the policy that
asserts only checks 10001 and 10005–10008. Checks 10002–10004 are not asserted then, so their
absence is not a failure. The full policy, below, runs once the enforcement keys ship.

The full policy asserts, among other things: the bundle is present (check 10001), `bypassPermissions`
is disabled (10002), the sandbox is enabled and fails closed (10003), the egress allowlist is
locked (10004), the PreToolUse hook points at ambitd on loopback (10005), the OTel destination
and protocol are pinned (10006, 10008), and ambitd is running (10007 — that one is D7's).

## What this alert asserts

- An SCA check in the `ambit_managed_settings` policy returned failed on this endpoint.
  `sca.check.title` names which one, in cleartext, and the check's own rationale says what it
  protects.
- For 100271: the same policy kept failing across three scans in two hours, correlated on
  `agent.name`.

## What it does not assert

- **The parent SID and the `sca.*` field names are unverified.** These rules chain from SCA alert
  rule 19007 and read `sca.policy_id`; neither was confirmed against the deployed ruleset.
  **If you have never seen a D12 alert on an endpoint where managed
  settings were demonstrably wrong, suspect the wiring before concluding the fleet is compliant.**
  A wrong parent does not error; the rule silently never fires.
- **SCA matches file text, not JSON semantics.** The checks are regexes over the settings file.
  A semantically equivalent but differently formatted bundle — reordered keys, different
  whitespace, a value written another valid way — can fail a check while being correct. That is a
  known false-positive mode and the first thing to rule out.
- **It does not say who changed it.** SCA reports state, not authorship. D6's FIM rules with
  `whodata` answer that, and a D6 alert on `managed-settings.json` in the same window is the other
  half of this story.
- **A failure is not always tampering.** A deployment race, a partially applied MDM profile, or a
  new Claude Code version changing a key's accepted form all produce failures.

## Triage

1. **Read which check failed.** The title says what control is not in force, and they are not
   equivalent: 10002 (bypass mode) and 10005 (the hook) mean the monitoring or the permission model
   is off; 10004 (egress allowlist) means the blast radius is wider than designed; 10001 means the
   bundle is simply absent.
2. **Rule out formatting.** Ask us for the endpoint's settings file and compare it against the
   expected bundle. A semantically-correct-but-differently-formatted file is a check to fix, not an
   incident.
3. **Correlate with D6.** A FIM alert on `managed-settings.json` (rule 100254) in the same window
   turns this into an edit with an attributed process. No D6 alert suggests the file never changed
   and the failure is a deployment or formatting problem.
4. **Check scope.** One endpoint is an endpoint problem. Many endpoints failing the same check at
   once is a deployment problem — and until it is fixed, the control is off across the fleet, which
   is worth saying plainly in the report.
5. **Check what the missing control was protecting.** If 10002 failed, look for D1 alerts on that
   endpoint: bypass mode being permitted and bypass mode being *used* are different facts, and both
   in the same window is the escalation.

## What requires us

- **The endpoint's managed-settings file**, to distinguish a formatting failure from a real one.
- **The MDM deployment state**: what was pushed, when, and whether it applied.
- **Confirmation of the SCA parent SID and field names**, once, on the deployed version — after
  which this caveat can be deleted from this runbook.

## Containment

1. Redeploy managed settings from the MDM source rather than editing the file on the endpoint;
   editing in place leaves the source of truth wrong.
2. Treat the endpoint as operating without that control for the window between the failure and
   its restoration, and say so in any report covering the period.
3. For a failure correlated with a D6 edit by an unexpected process, treat it as tampering:
   isolate the endpoint's credentials and review its recent sessions.

## Escalation

**Page** on 100270 for checks 10002, 10003 or 10005 — permission model, sandbox, event stream —
and on any 100270 correlated with a D6 FIM alert on the same file.

**Page** on 100271 regardless of which check, since a persistent failure is no longer a race.

**Queue** single failures of 10004, 10006 and 10008, and anything that resolves to formatting.

**Escalate as a deployment issue, not an incident**, when the same check fails across many
endpoints simultaneously.
