# Runbook R2 — Rule-of-Two gate (shadow verdicts)

**Rules:** 100320–100323 (group `ambit_r2_gate`). **MITRE:** T1552, T1041.

The Rule of Two says an agent should not hold all three of these at once: untrusted input it
has read (bit A), sensitive data it has touched (bit B), and the ability to change state or
reach the outside (bit C). ambitd keeps those bits per session and runs a gate on every tool
call. **In this milestone the gate runs in shadow: its verdict is recorded on the event and is
never returned to the agent.** The developer saw no prompt, and nothing was blocked. These
alerts say what enforcement *would* have done.

| Rule | Level | Means |
| --- | --- | --- |
| 100320 | 8 | Would have **denied** the tool call |
| 100321 | 6 | Would have **asked** the developer first |
| 100322 | 5 | This call completed all three Rule-of-Two properties (allowed by design, recorded) |
| 100323 | 13 | **Would have blocked, and the call carries a value from untrusted content** |

## What this alert asserts

- `policy_shadow` is `true`: the verdict was computed and not enforced. Nothing in the
  developer's session changed because of it.
- `policy_rule_id` names the row of the gate that matched, and `policy_reason` says it in words:
  - `r2.credential_after_a` (deny): a credential-zone file was read after the session had
    already read untrusted input.
  - `r2.publish_after_ab` (ask): a `git push` or package publish after untrusted input and
    sensitive data.
  - `r2.egress_after_ab` (deny): another outbound network command after both.
  - `r2.write_outside_after_ab` (ask): a write outside the working directory after both.
  - `r2.mcp_after_ab` (ask): an MCP call that can act, after both. A tool the operator labelled
    `read_only` never triggers it; an unlabelled tool on a server not classified internal
    always can.
  - `r2.trifecta` (allow, 100322): the call that gave the session all three properties.
- `r2_a`, `r2_b`, `r2_c` on the same event are the session's bits after the call.
  `policy_bundle_version` names the rule table that produced the verdict.
- For 100323: `prov_edge_*` are present too, meaning the call's input contains a value that
  first appeared in untrusted content earlier in the same session (see runbook D10 on edges).
  That composite is the page condition docs/03 names: a call that completes the Rule of Two
  *and* carries what the untrusted content supplied.

## What it does not assert

- **Not an attack.** The gate judges the sequence, not intent. The replay corpus shows it
  denying a developer who read a provider's docs and then their own `.env` to configure the
  client, which is ordinary work. That is why every row starts in shadow and why these levels
  are moderate.
- **"Session" may be stale.** The bits never clear within a session, so a long session can hold
  A and B from hours ago and the gate asks on an ordinary `git push` much later. A per-turn
  scoping is computed beside it for comparison and stays local. Ask us for it (below).
- **Not the content.** Paths are keyed digests, the command text does not cross, and the value
  behind an edge is a digest. Only zone labels (`credential`, `workdir`, …) and classes are in
  cleartext.
- **Blind to anything bit B misses.** B is set by credential paths, reads outside the working
  directory and secrets the edge classifier recognises. An agent sending the contents of an
  ordinary source file somewhere never sets B, so the A-and-B rows never fire for it.

## Triage

1. **Read the rule id and the bits.** `r2.credential_after_a` with `path_zone=credential`
   says which kind of credential path by zone, nothing more. For the A-and-B rows, the session
   reached B earlier: pull the session (`session_id`) and find the event where `r2_b` first
   turned true, which carries `r2_transition`.
2. **How long ago was A?** Pull the session's events in order. If the untrusted input (the
   event where `r2_a` turned true, often a `WebFetch` or an MCP result with `tool_mcp_server`)
   is in the same prompt turn (`prompt_id`), the sequence is tight; if it was many turns ago,
   this is the long-session case above and is usually benign.
3. **Is there an edge?** 100323, or `prov_edge_count` on the event, means the call carries a
   value from that untrusted content. Read runbook D10's triage for the edge. A deny plus an
   edge on an outbound call (`r2.egress_after_ab`) is the strongest single signal ambit
   produces.
4. **Benign pattern:** docs or package metadata fetched, then the developer's own config read,
   then a push to the team's usual remote, all prompted by a user request (`prompt_submit`
   events in between). **Malicious pattern:** an MCP or web result immediately followed, in the
   same turn and without a new prompt, by a credential read and an outbound command, especially
   with an edge.

## What requires us

- **The per-turn verdict and the full sequence.** The spool holds each event's alternative
  verdict under per-prompt-turn scoping, the exact tool inputs, and the ingest an edge points
  at. Request by `session_id` and `event_id`; expected turnaround one business day, same day for
  a 100323.
- **Digest resolution** for the credential path or the edge value, under the same request path
  as D10.

## Containment

None from this alert in this milestone: the verdict was not enforced and should not be. If
triage concludes the session was hijacked (typically a 100323 with a hostile edge), treat it as
D3/D1 containment: we revoke the developer's credentials that the session could reach. The
monitoring firm does not.

## Escalation

- **Page** on 100323 when the rule is `r2.egress_after_ab` or `r2.credential_after_a` and the
  edge class is `url`, `email` or `iban`.
- **Queue** 100320 and 100321 for review in batch. A burst of them from one endpoint (five or
  more in an hour) is worth a same-day look: it is either an attack in progress or a workflow the
  gate will block once enforced, and both need someone to know.
- 100322 alone is informational.
