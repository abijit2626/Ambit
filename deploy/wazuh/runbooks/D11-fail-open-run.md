# Runbook D11 — fail-open run

**Rules:** 100260–100261 (group `ambit_d11`). **MITRE:** T1562.001.

When ambitd is unavailable, a tool call proceeds without a decision. That is the correct
behavior — a monitoring component must never stop a developer working — and it means the
absence of a verdict has to be recorded, or an attacker gets a free window by making the daemon
unavailable.

| Rule | Level | Means |
| --- | --- | --- |
| 100260 | 5 | A tool call failed open: ambitd was unavailable |
| 100261 | 12 | **5+ fail-open calls on one endpoint within 300s** |

## Both rules are inert today

`policy_decision` is in the flattened schema and `fail_open` is one of its values, but ambitd has
no policy engine before M3 and emits no decision at all: every event today carries an empty
decision, which is what makes M0 and M1 behaviorally inert. Nothing can set `fail_open` yet.

Both rules are marked `ambit_pending_emitter` and are shipped now because the field, the value and
the shape are settled. **Do not read their silence as evidence that ambitd is never unavailable.**
Until M3, the detector that tells you collection stopped is D7, which reads the heartbeat and the
SCA process check — and that one works today.

When the gate does land, what follows applies.

## What this alert asserts

- A tool call reached Claude Code's permission pipeline and ambitd did not answer: the hook
  request timed out, was refused, or the daemon was gone. The call proceeded.
- For 100261: five or more such calls on one endpoint (`same_field` on `endpoint_id`) inside five
  minutes.

## What it does not assert

- **It does not assert an attack.** A restart, a deploy, a machine under heavy load, or a hook
  timeout under a slow disk all produce fail-open calls. The signal is sustained or repeated
  failure, not a single event.
- **It does not say what the calls were.** `tool_name` is on the event; whether any of them would
  have been denied is unknowable, because the decision never ran. That asymmetry is the point of
  the alert: the window is unjudged, not judged-and-allowed.
- **It does not mean the endpoint was unmonitored.** Failing open affects the *decision*; whether
  the event was still recorded depends on why ambitd was unavailable, which D7 answers.

## Triage

1. **Correlate with D7 immediately.** A fail-open burst with a 100311 or 100314 alert on the same
   endpoint is one incident with two views: D7 says the daemon was degraded or gone, D11 says
   tool calls went unjudged meanwhile. Without a D7 alert, the daemon was up and the hook path
   itself failed — a different and more suspicious story.
2. **Bound the window.** First and last fail-open timestamps for that `endpoint_id`. Every tool
   call in between was unjudged, and any later statement about that period has to say so.
3. **Read what ran in the window.** Pull the tool events for the endpoint between those
   timestamps. Credential reads, egress commands or MCP calls inside an unjudged window are worth
   reviewing individually, precisely because no gate looked at them.
4. **Check whether it recurs on one endpoint.** Repeated bursts on a single endpoint, with no
   deploy to explain them, is the shape that suggests someone is arranging for ambitd to be
   unavailable rather than tripping over it.
5. **Check for a D6 alert.** A configuration change removing or repointing the hook produces
   fail-open calls and is not an accident.

## What requires us

- **ambitd's log** for the window: why it was unavailable, and whether it was restarted.
- **Deploy and maintenance records** for the endpoint, which explain most single bursts.
- **Spool pull** for the unjudged window, if the spool kept writing while decisions were failing.

## Containment

1. Restore ambitd and confirm the hook configuration matches managed settings.
2. Review the unjudged window's tool calls rather than the fail-open events themselves — the
   events say a gap happened, the calls say what happened in it.
3. For repeated unexplained bursts on one endpoint, escalate as possible deliberate suppression
   and treat the endpoint as untrusted until explained.

## Escalation

**Page** on 100261 with no deploy or restart to explain it, and on any fail-open window that
contains a credential read or an egress command.

**Queue** isolated 100260 events and bursts that coincide with a known deploy.

**Report, do not page**, if these rules have never fired after M3 shipped: that is a wiring
question about whether the gate emits the decision, not a fleet with a perfect uptime record.
