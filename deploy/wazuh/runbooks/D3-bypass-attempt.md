# Runbook D3 — bypass attempt

**Rules:** 100220–100223 (group `ambit_d3`). **MITRE:** T1562.001, T1059.

Claude Code's permission layer refuses tool calls that policy does not allow. A refusal is
evidence that something asked for the action — and in a session that has ingested
untrusted content, what asked may not be the user.

| Rule | Level | Means |
| --- | --- | --- |
| 100220 | 10 | A tool call was denied by policy |
| 100221 | 13 | **5+ denials in one session within 300s** — probing |
| 100222 | 5 | A tool call failed (context) |
| 100223 | 3 | A permission prompt was raised (context) |

## What this alert asserts

- For 100220: Claude Code raised a `PermissionDenied` event for `tool_name` in this
  session. The policy layer did its job; the action did not happen.
- For 100221: five or more such denials in one session inside five minutes, correlated on
  `session_id`.
- 100222 and 100223 are context rules with no security claim of their own. 100223 exists
  because the *absence* of prompts across a session is D1's core shape, and an analyst
  needs to see whether prompts were happening at all.

## What it does not assert

- **It does not cover the invocation flags.** The detector catalogue names the
  permission-bypass CLI flags. ambitd sees hook events, not the agent's command line, so
  those are not observable here. What is observable is the resulting `permission_mode`
  (D1) and the control that forbids it (D12, SCA check 10002).
- **A denial is not an attack.** A developer declining a prompt produces one. So does a
  deny rule working exactly as intended — which is a control succeeding, not failing.
- **It does not tell you what was refused.** The flattened event carries `tool_name` but
  no error text and no tool input.

## Triage

1. **One denial or a pattern?** 100220 alone, in a session with prompts and ordinary
   work, is usually a developer saying no. 100221 is the alert that means something: five
   refusals in five minutes is something trying actions until one is allowed.
2. **Read the tool names across the denials.** Same `session_id`: the same tool refused
   five times is a retry loop or a confused agent. Five *different* tools refused is
   enumeration.
3. **Check whether anything succeeded after the denials.** A denial followed by a
   different route to the same effect — a `Bash` network command after a denied MCP write,
   say — is the sequence that matters. Look for rule 100300 or a D2 alert shortly after.
4. **Check for an explanation upstream.** D8 (untrusted instruction file) or D4 (drifted
   MCP metadata) in the same session tells you where the instruction to try came from.
5. **Check 100223.** Prompts happening means a human was likely present and may simply
   have declined. No prompts at all, plus denials, is the D1 shape.

## What requires us

- **Spool pull** for the denied calls: the tool inputs, which say what was actually
  attempted, and the error text. The flattened event deliberately carries neither.
- **The prompt** for the session, which usually resolves intent in one read.
- **The endpoint's policy**: which deny rules are in force, so "denied" can be read
  against what was expected to be denied.

## Containment

Not automatic. Note that the action was already blocked, so containment is about what
comes next, not about stopping the denied call.

1. For 100221, recommend ending the session and reviewing what the agent was working
   from — a poisoned instruction file or MCP description is the likely upstream.
2. Revoke credentials only if a later call succeeded at something equivalent.
3. Do not recommend relaxing the deny rule to "see what it would do".

## Escalation

**Page** on 100221, and on 100220 in a session with no prompt events where a subsequent
network or credential action succeeded.

**Queue** individual 100220 events for pattern review.

**Do not alert on** 100222 or 100223 by themselves; they exist as timeline context and are
levelled to stay out of the queue.
