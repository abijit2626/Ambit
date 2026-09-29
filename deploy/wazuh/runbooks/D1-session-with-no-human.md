# Runbook D1 — session with no human

**Rules:** 100200–100204 (group `ambit_d1`). **MITRE:** T1059, plus T1552.001 where
credentials are involved.

An agent running with no permission prompts does whatever it is told without a human
seeing the request. That is a legitimate configuration — CI, containers, scripted runs —
and it is also the s1ngularity signature: malware re-invoked a developer's own coding
agent with permission-bypass flags and used it to inventory SSH keys and cloud
credentials. This detector is about the *combination* of that mode with what the session
then did.

| Rule | Level | Means |
| --- | --- | --- |
| 100200 | 5 | A session started in `bypassPermissions` |
| 100201 | 13 | **Credential-zone access in such a session** — the core alert |
| 100202 | 12 | Outbound network command in such a session |
| 100203 | 12 | Secret material in a tool call from such a session |
| 100204 | 12 | Non-interactive entrypoint — **inert, see below** |

## What this alert asserts

- `permission_mode` was `bypassPermissions` for the session the event belongs to. This
  field is repeated on every event by design, so a tool call carries the shape of the
  session it happened in and no correlation is needed.
- For 100201: the tool touched a path in the `credential` zone, and `path_op` says
  whether it read or wrote. The zone label is cleartext; the path is a keyed digest.
- For 100203: `secret_hit_kinds` names the *kind* of secret the edge classifier
  recognized. The value never leaves the endpoint and is not in any event.

## What it does not assert

- **It does not assert the session was unattended.** `bypassPermissions` is a mode, not
  proof of absence. A developer can choose it deliberately, and in some teams that is
  routine — M0's baseline is what tells you whether it is routine here.
- **It does not cover D1's strongest half.** The detector catalogue specifies a
  non-interactive entrypoint and "SessionStart with no UserPromptSubmit". Neither is
  available from a rule: `agent_entrypoint` is in the schema but **nothing populates it**
  — the hook payload carries no entrypoint field and the OTel path has no equivalent —
  which is why rule 100204 is marked `ambit_pending_emitter` and will never fire until
  that changes. And absence of an event is not expressible in a rule engine at all.
  Treat D1 today as "bypass mode plus a sensitive action", not as "no human present".
- **It does not assert a human was absent even when no prompt appears.** Rule 100223
  (D3) records prompts; its absence across a session is suggestive, not conclusive.

## Triage

1. **Establish whether this endpoint is expected to run in bypass mode.** One question to
   the customer, answered once, removes most of this detector's volume. If the answer is
   yes for CI-shaped endpoints, ask for the endpoint_ids so 100200 can be routed
   differently for them.
2. **Read what the session did, not only how it started.** 100201, 100202 and 100203 are
   the alerts that matter. A bypass session that reads only workdir files is a
   configuration choice; one that reads `~/.ssh` in its first minute is the documented
   attack.
3. **Check the session's prompt events.** Same `session_id`: is there any
   `kind` = `prompt_submit`, or any rule 100223 permission prompt? A session with
   credential reads and no prompt at all is the shape worth paging on, even though the
   rule cannot assert it.
4. **Check the order.** Pull events for the `session_id` in sequence. Credential access
   within seconds of `session_start`, before any prompt, is automation. Credential access
   after a prompt mentioning deployment or credentials is a developer doing their job.
5. **Correlate with D8 and D4.** An untrusted instruction file (rule 100290) or drifted
   MCP metadata (100234) in the same session supplies the "why": something told the agent
   to do this.

## What requires us

- **Digest resolution** for `path_digest` on 100201, to name the credential file.
- **Spool pull** for the session: the prompts, the tool inputs, and the ordering the
  flattened stream summarizes. For this detector the prompt text is the decisive artifact
  and it never crosses to Wazuh.
- **Endpoint classification**: whether this endpoint is a CI runner or a developer laptop.

## Containment

Not automatic, not yours to execute. Recommend, in order:

1. Revoke the credentials whose paths were touched. For 100201 this is the first action
   and it does not wait for full analysis.
2. Ask us to confirm managed settings still disable `bypassPermissions` where they should
   — that is SCA check 10002, and a D12 alert in the same window changes this from a
   configuration choice into a control failure.
3. Terminate the session only with the customer's agreement: it is a developer's working
   session unless proven otherwise.

## Escalation

**Page** on 100201, and on 100202 or 100203 in a session with no prompt events.

**Queue** 100200 on endpoints not known to run in bypass mode, and 100202 or 100203 where
prompts are present.

**Suppress after confirmation** 100200 on endpoints the customer has identified as CI.
Note the endpoint_ids in the engagement record rather than silently closing them.
