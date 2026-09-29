# 09 — Q13 decided: Adrian does not cover M1/M2, build continues

[07](07-open-questions.md) Q13 asked whether
[`secureagentics/adrian`](https://github.com/secureagentics/adrian) already covers
M1 and M2's ground, and said the existing assessment in [06](06-prior-art.md) "rests
on a one-line description rather than on reading it" and should not be trusted as
written. This is that reading, with evidence.

**Decision: build continues. Adrian does not cover M1 or M2's ground, and the reason
is architectural rather than a feature gap** — its entire detection mechanism is the
signal [03](03-detection.md) identifies as the fragile one, promoted to inline
blocking authority, which is the one thing that document says never to do. Nothing
here is taken from Adrian into ambit; one thing is taken as a warning.

Evaluated at commit `73c6c1c`, 2026-09-15, Apache-2.0, company-backed (SecureAgentics
Ltd, UK, CLA on file), 101 Go tests and 483 Python tests, active CI. This is a real,
maintained project, not a toy — the finding below is architectural, not a quality
judgment.

## What was checked, and how

The four gaps the provisional assessment listed, each checked against the actual
code rather than the README:

| # | Provisional question | Resolved by |
| --- | --- | --- |
| 1 | Reasoning traces vs. actions | `backend/internal/engine/{engine,trace,system_prompt.md}` |
| 2 | Per-session vs. fleet | `backend/internal/engine/window.go`, `backend/internal/store/{events,verdicts,stats}.go` |
| 3 | SIEM-native vs. standalone | repo-wide grep, `backend/internal/notifications/`, `docs/ARCHITECTURE.md` |
| 4 | Rule-of-Two / provenance | repo-wide grep, `backend/internal/engine/trace.go` |

A fifth question wasn't in the provisional list and turned out to be the most
consequential finding: **does Adrian already gate tool calls inline**, the thing
ambit's M3 has not started. It does — checked against
`integrations/claude-code/adrian_cc/agent.py` and `sdk/python/adrian/handler.py`.

## 1 — Reasoning traces are the entire mechanism, not a corroborating signal

Confirmed, and stronger than the provisional read expected. Adrian's classifier is a
single LLM call per event. `system_prompt.md` states the input plainly: *"You will
receive agent traces containing the agent's chain-of-thought reasoning, tool calls,
and tool outputs"* and asks for exactly one MAD-taxonomy code (M0 benign through M4
maximum severity) with no other signal. `engine.Classifier` (`engine.go`) takes one
`PairedEvent` — which carries reasoning, per `trace.go`'s comment "every untrusted
interpolation... LLM output, is wrapped" — and returns one `Verdict`. There is no
second layer: no deterministic pre-filter, no rule engine, no fallback detector. If
the LLM call fails, the documented behavior (`docs/ARCHITECTURE.md`) is fail-open to
a synthetic benign verdict.

[03](03-detection.md) states the finding this project rests on: *"reasoning-level
monitoring is a weakening signal and action-level monitoring is the durable one,"*
citing AgentDojo's 11%→81% result against adaptive attacks that specifically target
chain-of-thought monitors. Adrian's architecture is the position that document argues
against, not a variant of the position it argues for. This is not a gap to fill; it
is the premise Adrian is built on.

## 2 — Per-key, not fleet. No cross-session correlation exists to find

Confirmed. `SlidingWindow` (`window.go`) is keyed by `(session_id, invocation_id,
agent_id)`, single-process, in-memory, a 16-slot ring buffer per key with a per-key
mutex. The comment is explicit: *"Restart loses warm state... no correctness
impact"* — there is no fleet-wide state to lose. The store side confirms it: every
query in `store/events.go`, `store/verdicts.go` and `store/stats.go` is a
single-table filter or a time-windowed count (`StatsOverview`, `StatsActivity`).
None joins across sessions, agents, or endpoints.

This means D2 (credential sweep across unrelated directories), D9 (egress anomaly
against an endpoint's baseline) and D10 (cross-agent fingerprint propagation) have no
home in Adrian's architecture — not "not implemented yet," but structurally absent,
because the system keeps no state broader than one conversation. These three
detectors are exactly the reason [02](02-architecture.md) puts Wazuh in this design
at all.

## 3 — Standalone, not SIEM-native. No adjacency, not even partial

Confirmed, more completely than expected. A case-insensitive search for `syslog`,
`siem`, `wazuh`, `splunk` and `cef` across the entire repository — Go, Python,
TypeScript, Markdown — returns zero matches. The only outbound notification path is
a Discord webhook (`backend/internal/notifications/dispatcher.go`). The dashboard
(`frontend/`) is a standalone Next.js app with its own session-cookie auth and its
own SQLite store. There is no ATT&CK tagging, no runbook concept, no flattened
schema shaped for a decoder's field-count limit — none of the SIEM-adjacent
machinery [04](04-data-model.md) is built around.

## 4 — No Rule-of-Two accounting, no provenance, no keyed fingerprinting

Confirmed. A search for `taint`, `provenance`, `rule_of_two`, `rule.of.two` and
`fingerprint` across the repository returns nothing relevant. The one thing that
looked adjacent on first read — `Handle.Guid()` in `window.go`, described as a
"per-conversation untrusted-tag id" — turned out to be a prompt-injection defense
for the classifier's *own* prompt: `trace.go` wraps untrusted interpolations (tool
output, agent prompts) in a random per-conversation delimiter so the classifying LLM
treats them as data rather than instructions. It hardens the judge against the
content it is judging. It does not track which of three properties a session has
accumulated, and it does not gate deterministically on the third the way
[03](03-detection.md)'s R2 gate does. There is a MAD code for the *outcome* —
`M2.d Following injected instructions over policy` — but reaching it means the LLM
judged the trace that way, not that a bit got set and a rule fired.

D4 and D5 have no equivalent either. Adrian's MCP handling
(`backend/internal/api/handlers_mcp.go`, `backend/internal/store/mcp.go`,
`sdk/python/adrian/mcp.py`) records one row per `(session_id, name, transport,
endpoint)` from inventory frames — a server-seen list, nothing else. No
description, no input schema, no hash, no baseline, no drift verdict. A search for
`hash`, `baseline`, `description` and `drift` in `mcp.py` returns nothing. D4 and D5
are [02](02-architecture.md)'s `mcp-interpose` design, still unimplemented as of this
evaluation; Adrian is not a shortcut to it.

## 5 — What the provisional assessment missed: Adrian already blocks

Not in the original four questions, and the most important finding here. Adrian's
Claude Code plugin has a real `PreToolUse` hook
(`integrations/claude-code/hooks/hooks.json`) that, in `MODE_BLOCK`, **waits
synchronously for a verdict and returns `permissionDecision: "deny"`** on M3/M4
(`adrian_cc/agent.py`, `_handle_pre` / `_verdict_action`). There is also a
`MODE_HITL` that turns an M3/M4 verdict into Claude Code's native approval prompt,
backed by a review queue in the dashboard, and a `MODE_ALERT` that never enforces.
The mode is server-driven per `PolicySnapshot`, not a client choice.

This is materially more than ambit has shipped: M3 has not started here, and every
hook response is `{}` by design (docs/05). Adrian ships a working inline gate today.

The default wait is `ADRIAN_CC_VERDICT_TIMEOUT=15` seconds — a synchronous network
round trip to the backend, which itself calls an LLM (local llama.cpp or configured
endpoint) and waits on inference. [02](02-architecture.md)'s latency budget for
`ambitd`'s `PreToolUse` response is under 5 milliseconds, three orders of magnitude
tighter, because the gate is deterministic bit comparison with no model call in the
synchronous path. Adrian's own generous timeout is consistent with its architecture,
not a bug in it — but it means the two designs have made opposite bets about what
belongs inline. [03](03-detection.md)'s layer ordering states the bet this project
makes explicitly: *"deploy in that order, and never let a lower-reliability layer
block a tool call inline."* Layer 3 there — semantic, "least reliable," advisory and
aggregate only — is what Adrian runs as its *only* layer, given the authority to
deny a tool call outright. That is not a smaller version of ambit's design; it is
the configuration ambit's own design document warns against.

## The three outcomes, and which one this is

Q13 named three acceptable outcomes and one that would not be: build because it
does not fit, adopt and contribute upstream because it fits well, narrow `ambitd` to
the gap because it partly fits, or — unacceptable — discover the overlap at M3
having built the whole thing regardless.

**Does not fit, cleanly, for a reason stronger than the provisional read expected.**
This is not "different scope, no conflict." It is "the same problem, solved by
promoting the exact mechanism this design treats as too unreliable to trust alone
into the role of sole inline authority." Adopting Adrian as the M1/M2 base would mean
either accepting that inversion or stripping out the part of Adrian that makes it
Adrian. Partly-fits and narrow-the-gap don't apply either: there is no fleet
correlation, SIEM integration, Rule-of-Two accounting, or MCP metadata baseline in
Adrian to narrow around — the gap is the entire deterministic layer this project
contributes, not a piece of it.

## What's worth taking, and what's worth a warning

**Nothing is taken into ambit's design or code.** The one candidate — the
per-conversation delimiter defense in `trace.go` — solves a problem ambit's LLM-free
synchronous path doesn't have; it becomes relevant only if M4's goal-drift scorer
ever needs to protect its own prompt from the content it scores, worth a one-line
note in that milestone's design and nothing before.

**One warning, worth stating for whoever reviews an MSSP conversation or a customer
comparison.** If ambit is ever compared against Adrian by someone who has read both
project pages rather than both codebases, the comparison will look backwards:
Adrian already blocks tool calls today, and ambit does not until M3. The substance
underneath is the opposite of what that surface comparison suggests — Adrian blocks
on the signal this design's own research says degrades fastest under adaptive
attack, unconditionally once a code crosses M3, with no lower-reliability-layers-
never-gate-inline discipline — but "it already blocks and yours doesn't" is a true
sentence someone will say, and the answer needs to be ready rather than improvised.

## What would reverse this

- Adrian adds cross-session or cross-endpoint correlation, a SIEM export path, or
  metadata-hash MCP baselining — any one of these closes a specific gap identified
  above and the specific gap, not the whole evaluation, should be re-run against it.
- ambit's own M4 goal-drift work finds that an LLM-judge layer is unavoidable at some
  tier; if so, Adrian's prompt-hardening and few-shot-window mechanics
  (`engine/prompt.go`, `engine/few_shot.md`) are worth a focused second read as
  reference material for that milestone specifically, not as a reason to adopt the
  whole project.
- A future decision to trust reasoning-trace monitoring as more than advisory would
  reopen this from the other direction — but that is a reversal of [03](03-detection.md)'s
  own finding, not of this evaluation.

## Reproducing this evaluation

```sh
git clone --depth 1 https://github.com/secureagentics/adrian   # 73c6c1c, 2026-09-15

# Finding 1: the entire detection mechanism reads reasoning traces.
cat backend/internal/engine/system_prompt.md
cat backend/internal/engine/engine.go

# Finding 2: per-key state only, no cross-session queries.
sed -n '1,60p' backend/internal/engine/window.go
grep -n "SELECT" backend/internal/store/events.go backend/internal/store/stats.go

# Finding 3: no SIEM/syslog adjacency anywhere in the tree.
grep -rli "syslog\|siem\|wazuh\|splunk\|cef\b" --include='*.go' --include='*.md' \
  --include='*.ts' --include='*.py' .

# Finding 4: no taint/provenance/fingerprint concept; MCP handling is inventory only.
grep -rli "taint\|provenance\|rule_of_two\|fingerprint" --include='*.go' --include='*.py' .
grep -n "hash\|baseline\|description\|drift" sdk/python/adrian/mcp.py   # no hits

# Finding 5: real inline blocking exists today, on a ~15s synchronous budget.
grep -n "MODE_BLOCK\|permissionDecision\|VERDICT_TIMEOUT" \
  integrations/claude-code/adrian_cc/agent.py
```
