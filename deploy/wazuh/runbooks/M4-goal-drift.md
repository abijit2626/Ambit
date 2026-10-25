# Runbook M4 — goal drift

**Rules:** 100330–100331 (group `ambit_m4`). **MITRE:** none (see below).

Each Claude Code session starts from a request a person typed. When an agent reads something
that carries instructions (a web page, an issue, a tool result) and follows them, its actions
stop serving that request: a payment to a different recipient, a post to a site nobody named, a
file sent somewhere it was never meant to go. Each step can look like ordinary work. This
detector asks a model the one question that does not depend on knowing the attack: **does this
action serve what the user asked for?**

| Rule | Level | Means |
| --- | --- | --- |
| 100330 | 8 | The judge said a tool call that carries a value from content the agent read does not serve the user's request |
| 100331 | 12 | The same, in a session that can now change state or reach the outside (Rule-of-Two bit C): **page** |

## What this alert asserts

- The endpoint has `goal_drift` turned on. ambitd sent the session's latest user prompt and this
  tool call's name and arguments, both redacted and truncated, to the configured model (Claude
  Haiku 5.5 by default), and the model answered UNRELATED. `goal_drift_score` is 1 for UNRELATED;
  RELATED scores 0 and never leaves the endpoint.
- The tool call carries a provenance edge: a value in its arguments matched something the
  session read from untrusted content. Only such calls are judged; the rest are never sent. The
  edge is on the tool event, not on this one: find that event by `tool_use_id` (it alerted as
  100283 or higher), where `prov_edge_class` says what kind of value matched and `prov_edge_from`
  names the event that brought it in.
- `tool_use_id` finds the tool call itself in the endpoint's spool, where the full event (and
  this score) is kept.

## What it does not assert

- **It is a model's judgment, not a fact.** On the prototype (docs/03-detection.md, AgentDojo
  traces) this combination flagged 30 of 47 hostile and 1 of 132 benign actions with an edge.
  Legitimate engineering is often "unrelated" to the literal request: reading an unrelated file to
  understand a codebase, fixing a neighbouring broken test.
- **The judge never saw the tool results**, so it cannot tell you what the agent read; the edge
  and the spool can.
- **It can be argued with.** The action's arguments may carry text an attacker wrote, and an LLM
  judge is promptable. The prompt fences the arguments as data, but a RELATED verdict is not proof
  of innocence: absence of this alert means nothing.
- **No MITRE technique.** "Does not serve the user's request" has no honest ATT&CK mapping, and a
  forced one would mislead triage more than help it.

## Triage

1. **Read the action against the request.** The alert carries the tool name; the endpoint's spool
   (via us) carries the redacted prompt and arguments. Most false positives are obvious once both
   are side by side.
2. **Follow the edge.** On the tool event (same `tool_use_id`), `prov_edge_from` is the event that
   brought the value in. If that was a web
   page, an MCP result or a file outside the trusted repositories, ask what it said.
3. **Look for the rest of the shape.** In the same session: an R2 gate shadow verdict (100320,
   100323), a D9 network command or sandbox denial, a credential read (D2). A 100331 already means
   the session can act outward.
4. **Check how often this session drifts.** One unrelated call in a long session is common; several
   in a row, all with edges to the same ingest, is not.

## What requires us

- The redacted prompt and tool arguments from the endpoint's spool (`trajectory.jsonl`, found by
  `tool_use_id`).
- The ingest event named by `prov_edge_from`, for what the agent read.
- Whether the user meant it: only they know whether the request implied the action.

## Containment

1. For 100331, treat the session as possibly following injected instructions: ask the developer to
   stop it and review its recent actions before anything else runs.
2. If the edge leads to a credential or an outbound destination, handle it as D2 or D9.
3. Nothing was blocked: goal drift is observe-only, like every detector in this milestone.

## Escalation

**Page** on 100331. **Queue** 100330 for same-day review. Repeated false positives on one kind of
action are a tuning request for us, not a reason to ignore the rule.
