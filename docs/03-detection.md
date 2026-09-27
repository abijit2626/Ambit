# 03 — Detection

Three layers, in increasing order of cleverness and decreasing order of
reliability. Deploy them in that order, and never let a lower-reliability layer
block a tool call inline.

1. **Deterministic** — Rule-of-Two accounting, credential-path access, egress,
   config drift, MCP metadata drift, session-shape rules. Cheap, explainable,
   suitable for gating.
2. **Provenance** — did this action derive from untrusted content. Heuristic but
   structural. Suitable for gating on high-impact action classes.
3. **Semantic** — does this action serve the stated objective. Highest value
   against covert side tasks, least reliable. Advisory and aggregate only.

## Layer 1 — Rule-of-Two accounting

Meta's Agents Rule of Two (published 31 October 2025) states that until prompt
injection can be reliably detected and refused, an agent should satisfy **no more
than two of three properties within a session**: processing untrusted input,
accessing sensitive data, and changing state or communicating externally. An agent
needing all three without a fresh context window should not operate autonomously
and requires at minimum human-in-the-loop supervision.

Everything needed to track this is in the hook stream. Nobody tracks it. So:

Maintain three bits per session, monotonically set (never cleared within a
session — see [07](07-open-questions.md) for the compaction and `/clear` question).

**Bit A — untrusted input ingested.** Set by:
- `WebFetch` / `WebSearch` result from any domain not on the trusted-content list
- Bash output from a command that made a network request
- An MCP tool result from a server whose trust label is not `internal`, or any
  tool annotated `openWorldHint: true`
- `InstructionsLoaded` for a `CLAUDE.md` or `.claude/rules/*.md` under a path not
  on the trusted-repo list — a poisoned instruction file in a cloned repo
- A `Read` of a file in an untrusted zone: `node_modules/`, vendored dependencies,
  `~/Downloads`, anything git reports as untracked-and-recently-created
- Issue / PR / ticket / email bodies arriving through any MCP tool

**Bit B — sensitive data accessed.** Set by:
- Read of a credential path: `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`,
  `**/.env*`, `.npmrc`, `.netrc`, `**/id_*`, keystores, wallet files
- Read of a file whose content trips a secrets classifier at the edge
- Read outside the session's working-directory boundary
- An MCP tool returning data from a system labelled sensitive

**Bit C — state change or external communication.** Set by:
- Bash command with network capability (`curl`, `wget`, `nc`, `ssh`, `scp`, `git
  push`, package publish)
- `Write` / `Edit` outside the working directory
- An MCP tool that is not `readOnlyHint: true` — and note the asymmetry from
  [02](02-architecture.md): a server *claiming* read-only earns no relaxation, so
  in practice treat every MCP tool on a non-internal server as C-setting unless
  an operator has explicitly classified it
- Git push, PR creation, package publish, any outbound API write

**The gate.** A `PreToolUse` call that would set the third bit is evaluated
against the policy for that action class:

| Action class | Third-bit policy |
| --- | --- |
| Credential-path read after A | `deny` |
| Outbound network from Bash after A and B | `deny` |
| `git push` / publish after A and B | `ask` |
| Write outside working dir after A and B | `ask` |
| MCP non-read-only tool after A and B | `ask` |
| Everything else | `allow` + alert |

Start every one of these at `ask` or `allow`+alert in production and promote to
`deny` only with baseline data. See [05](05-build-plan.md).

**Honest limitation.** The rule is stated over a session, and "session" is doing
real work in that sentence. Compaction, `/clear`, subagents, and long-running
sessions all make the boundary ambiguous, and a monotonic bit over an 8-hour
session will saturate to all-three and gate everything. This is the single biggest
open design problem in the system and is treated as such in
[07](07-open-questions.md).

## Layer 2 — Provenance

The goal: link "untrusted content entered here" to "this action happened." CaMeL
(*Defeating Prompt Injections by Design*, arXiv:2503.18813) does this soundly with
a custom Python interpreter that tracks a dataflow graph over every variable, a
privileged LLM that never touches untrusted data, and a quarantined LLM with no
tool access — solving 77% of AgentDojo tasks with provable security.

**We cannot do that.** CaMeL requires control of the interpreter and the agent
loop. Claude Code is a black box that hands us events. So this layer is an
explicitly unsound approximation, and the design should say so rather than imply
taint-tracking guarantees it does not have.

### 2a — Session taint (sound, coarse)

Bit A from layer 1, carried as a label. Reliable, and useless on its own for
attributing a *specific* action.

### 2b — Content fingerprinting (unsound, specific)

At every untrusted ingest, extract and store fingerprints of the content:

- Registrable domains and full URLs
- Email addresses
- High-entropy tokens (≥ 20 chars, entropy above threshold) — keys, blobs, IDs
- IP addresses and host:port pairs
- Rare n-grams: shingles whose corpus frequency is below a threshold, so common
  English is excluded

On every `PreToolUse`, extract the same classes from `tool_input` and intersect
with the session's ingest fingerprints. A hit yields a **provenance edge**:
`action ← ingest`, with the matched token class as evidence.

This is the detector that catches the canonical exfiltration: the attacker's
domain, webhook URL, or email address appears in the injected content and then
appears in a `curl` argument or a `Write`. The evidence is concrete and
human-reviewable, which matters for a gate.

Failure modes, both directions:
- **False negatives from paraphrase.** The model re-wording the instruction, or
  reconstructing the destination from memory, defeats it entirely. The edge is
  lost; session taint remains.
- **False positives from legitimate carry-through.** An agent asked to summarize a
  page and write the summary to a file legitimately carries content across. Domain
  and high-entropy matches are far more specific than n-gram matches; weight them
  accordingly and consider n-gram matches advisory only.

### 2c — Causal ordering

Using `prompt.id` and `event.sequence`, detect *first occurrence after ingest*:
within a prompt turn, an action class the session has not exhibited before,
occurring after an untrusted ingest. First credential read, first outbound
connection, first write outside the working directory.

Weak alone. Valuable as a multiplier on 2a: "session tainted, and then did
something it had never done in 400 prior turns" is a much better signal than
either half.

## Layer 3 — Goal drift

This is the direct answer to the covert-side-task finding, and the reason to build
any of this.

SHADE-Arena (Kutasov et al., arXiv:2506.15740 — Anthropic with Redwood Research,
Scale AI and others, June 2025) places an agent in a simulated workplace with a
benign main task plus a hidden malicious side task, and scores an LLM monitor that
does not know the side task. The empirical finding that matters for us: side-task
success depended heavily on the model having a hidden scratchpad the monitor could
not see, and the published follow-ups consistently report that **monitors watching
the model's actions caught covert side tasks far more reliably than monitors
watching only its reasoning.** Anthropic's Claude Opus 4.6 Sabotage Risk Report
(February 2026) reports ~18% side-task success under monitoring with thinking
available, ~16% without *(vendor-reported; not independently replicated)*.

Reasoning-level monitoring is the fragile signal. Action-level monitoring is the
durable one. So the detector is:

**Does this action serve the objective the user actually stated?**

- `UserPromptSubmit` gives `user_input` — the declared objective, verbatim, before
  the model has touched it.
- Each subsequent tool call is scored for relevance to that objective by a small
  cheap model, given the objective, the action, and a compact summary of the
  session so far.
- Score runs **asynchronously**. It never gates a `PreToolUse` inline: it is too
  slow for a 5 ms budget and too unreliable to block a developer's file read.
- Output feeds a per-session drift score and a review queue. Sustained drift, or a
  single action scored as strongly unrelated *and* carrying a provenance edge *and*
  setting a Rule-of-Two third bit, is a page.

Two things this buys that nothing else does: it catches the case where every
individual action is permitted (GTG-1002's decomposition — each step defensible in
isolation), and it needs no knowledge of the attack, only of the task.

Two things to be clear-eyed about: an LLM judge scoring actions is itself
promptable, so the scorer must never see raw untrusted content, only structured
action descriptions, and its prompt must be treated as a security boundary. And
"unrelated to the stated objective" describes a great deal of legitimate
engineering work — reading unrelated files to understand a codebase, fixing an
unrelated broken test. Expect this to be noisy and budget for tuning.

## Detector catalogue

Day-one deterministic detectors, in rough order of signal-to-noise:

| # | Detector | Signal |
| --- | --- | --- |
| D1 | **Session with no human.** Non-interactive entrypoint, `permission_mode` = `bypassPermissions`, `SessionStart` with no `UserPromptSubmit` following, immediate credential-path reads. | The s1ngularity signature. Highest-confidence detector in the system. |
| D2 | **Credential sweep.** N credential-path reads within a short window, especially across unrelated directories. | Staging for exfiltration |
| D3 | **Bypass attempt.** Any observed invocation with `--dangerously-skip-permissions` / `--yolo` / `--trust-all-tools`, or `permission_mode` = `bypassPermissions` where managed policy disables it. | Active attack or serious policy violation |
| D4 | **MCP metadata drift.** Tool name / description / schema hash differs from approved baseline. | Rug pull |
| D5 | **Instruction-shaped tool description.** Imperative language, role assertions, or references to other servers' tools in a description or schema. | Tool poisoning / shadowing |
| D6 | **Config tamper.** `ConfigChange` or `FileChanged` on settings files; managed-settings mismatch reported by `agentd` at startup. | Suppression attempt |
| D7 | **Telemetry gap.** Enrolled endpoint silent while active; OTel stream present with no hook stream, or vice versa. | Daemon suppression |
| D8 | **Poisoned instruction file.** `InstructionsLoaded` for a `CLAUDE.md` / `.claude/rules/*.md` under a newly cloned or untrusted path. | Repo-carried injection |
| D9 | **Egress anomaly.** Outbound volume or destination outside the endpoint's established profile; any allowlist denial. | Exfiltration |
| D10 | **Cross-agent fingerprint match.** An ingest fingerprint in session X matching an output fingerprint from session Y. | Prompt Infection / propagation |
| D11 | **Fail-open run.** Repeated `agentd` unavailability records. | Suppression |

Then, in order: R2 gate (layer 1), provenance edges (layer 2), goal drift
(layer 3).

## Validating the detectors

Detectors need adversarial tests, and building our own attack corpus from scratch
would be the wrong use of time when three public ones exist:

- **AgentDojo** (ETH Zurich) — indirect prompt injection / agent hijacking
  benchmark. NIST CAISI used it to show attack success rising from 11% for the
  strongest baseline attack to 81% for a stronger adaptive attack on Claude 3.5
  Sonnet, which is the empirical reason not to rely on injection *detection*.
- **SHADE-Arena** — the covert-side-task format layer 3 is built to catch.
- **ControlArena** (UK AISI with Redwood Research) — control protocols, settings,
  and model organisms.

Use them as the regression suite: replay their trajectories through `agentd` and
measure detection rate and false-positive rate per detector. NIST's finding above
carries a methodological warning we should adopt: **evaluate against attacks
adapted to our detectors, not only generic baselines.** A detector tuned on
baseline attacks will overstate its own coverage.
