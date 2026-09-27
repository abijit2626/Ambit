# 05 — Build plan

## The sequencing argument

Observe before enforce, and mean it.

A `PreToolUse` hook that returns `deny` sits in the critical path of every tool
call on every endpoint. A false deny does not degrade gracefully — it stops a
developer mid-task, with a confusing reason, and it does so fleet-wide
simultaneously. Two or three of those and the managed settings get an exception
carved out, and the system is over.

There is also no way to tune a threshold without a baseline. "Reads a credential
path after fetching a web page" sounds obviously bad until you learn that the
team's deploy script does exactly that forty times a day. Every detector in
[03](03-detection.md) needs its false-positive rate measured against real traffic
before it gates anything.

So: M0 and M1 ship with no ability to block. Enforcement begins at M3, starts at
`ask` rather than `deny`, and is promoted per-rule on evidence.

## M0 — Observe

**Goal:** answer "what did all our agents do yesterday," and nothing more.

- `agentd`: HTTP hook endpoint on localhost, OTLP receiver, local spool, push to
  ingest. No policy engine — every hook response is empty (no decision).
- Normalized event schema v1 ([04](04-data-model.md)), edge redaction, keyed
  feature extraction.
- Managed settings bundle: hooks for all observation events, OTel enabled and
  destination-pinned. **No permission changes, no sandbox changes.**
- Fleet: ingest, append-only store, columnar analytics, enrollment, heartbeat.
- A single dashboard: sessions, tool-call volume, MCP servers in use, permission
  modes observed, entrypoints observed.

**Exit criteria:** deployed to a volunteer cohort (5–10 endpoints). p99 hook
response under 5 ms. Zero developer-visible behavior change — verified by asking
them, not by assuming. Event loss under 0.1%.

**Deliberately not in M0:** any decision, any alert, any blocking. If M0 changes
one thing about how a developer's session behaves, it has failed.

## M1 — Inventory and drift

**Goal:** know what MCP surface the fleet actually trusts, and notice when it
changes.

- `mcp-interpose`: wraps configured servers, captures `tools/list`, hashes name +
  description + schema per tool, records annotations, labels results.
- Approval baseline: the first-seen metadata hash per server/tool, with an explicit
  operator approval step.
- Detectors D4 (metadata drift), D5 (instruction-shaped descriptions), D6 (config
  tamper), D7 (telemetry gap), D8 (poisoned instruction file), D11 (fail-open run).
- Alerting to a review queue. Still no blocking.

**Exit criteria:** every MCP server the cohort uses is inventoried with an approved
baseline. A deliberately mutated test server triggers D4 within one session. D7
fires when `agentd` is killed on a test endpoint.

**Why this is before provenance:** it is the cheapest real security value in the
plan. Rug-pull and tool-poisoning detection is a hash comparison and a regex, it
has a naturally near-zero false-positive rate, and it covers adversary A3 outright.
Provenance is more interesting and much more work.

## M2 — Provenance and Rule-of-Two, alert only

**Goal:** produce the signals that later gate, and measure how noisy they are.

- Provenance engine in `agentd`: session taint (2a), content fingerprinting (2b),
  causal ordering (2c). Edges shipped, not raw content.
- Rule-of-Two accounting: the three bits, with the zone and annotation
  classification tables that set them.
- Every gate from [03](03-detection.md) evaluated and **recorded as the decision it
  would have made** — shadow mode. No decision returned to Claude Code.
- Detectors D1 (session with no human), D2 (credential sweep), D3 (bypass attempt),
  D9 (egress anomaly).
- Replay harness: AgentDojo, SHADE-Arena, and ControlArena trajectories through
  `agentd`, per-detector detection and false-positive rates.

**Exit criteria:** the shadow-mode report shows, per rule, how many times it would
have blocked and a human-reviewed verdict on each. **A rule does not advance to M3
until its would-have-blocked set is reviewed and its false-positive rate is
acceptable for its action class.** Session-boundary behavior (compaction, `/clear`,
long sessions, subagents) is measured and the question in [07](07-open-questions.md)
is answered with data rather than argument.

This is the milestone most likely to reveal that a detector is unusable. That is
the point of it.

## M3 — Enforce

**Goal:** actually stop things, without becoming the reason the project gets
switched off.

- Policy engine returns real decisions. Signed policy bundles, version-pinned,
  `agentd` refusing unsigned or downgraded bundles.
- Split fail policy from [02](02-architecture.md): narrow fail-closed set,
  fail-open plus record for everything else.
- Managed settings tighten: `disableBypassPermissionsMode`, sandbox
  `failIfUnavailable`, `allowManagedDomainsOnly` with a curated allowlist.
- **Promotion ladder per rule:** shadow → `ask` → `deny`. A rule sits at `ask` for
  a minimum of two weeks with a reviewed false-positive rate before `deny`.
- A developer-facing escape hatch: when a rule blocks, the reason is specific, it
  names the rule, and there is a fast path to request an exception. A gate with no
  appeal path gets circumvented.

**Exit criteria:** the fail-closed set is enumerated and justified. Documented
rollback: one bundle version revert, and a kill switch that returns `agentd` to
observe-only without touching managed settings.

## M4 — Goal drift

**Goal:** catch the covert side task — the thing the research is actually about.

- Objective capture from `UserPromptSubmit`.
- Async scoring of actions against the declared objective by a small model, over
  structured action descriptions only. **The scorer never sees raw untrusted
  content** — it is an LLM in the security path and therefore itself a prompt-
  injection target.
- Per-session drift score, review queue, and a composite page condition: strongly
  unrelated action *and* a provenance edge *and* an R2 third bit.
- Measured against SHADE-Arena as the benchmark it was designed for.

**Exit criteria:** measured detection rate on SHADE-Arena-style covert side tasks,
and a false-positive rate against the cohort's real traffic that a human review
queue can absorb. If the queue is unworkable, the composite condition tightens
rather than the detector shipping as a gate.

Stays advisory. It does not gate inline in M4, and promoting it later requires a
separate argument.

## M5 — Fleet correlation

**Goal:** the multi-agent problems.

- D10: cross-session fingerprint matching — one session's ingest appearing as
  another's output (Prompt Infection / propagation).
- Session-shape analysis for A4: decomposition patterns across sessions and
  operators, aggregate review rather than per-action blocking.
- Per-endpoint and per-user behavioral baselines for D9.

**Exit criteria:** a seeded propagation test — inject a fingerprint into one
session's ingest, have it surface in a second session — is detected.

## Dependencies

```
M0 (observe) ──► M1 (inventory/drift) ──► M3 (enforce)
     │                                      ▲
     └──────────► M2 (provenance/R2) ───────┘
                       │
                       ├──► M4 (goal drift)
                       └──► M5 (fleet correlation)
```

M1 and M2 are independent after M0 and can run in parallel. M3 requires both. M4
and M5 require M2's provenance layer.

## What could make this not worth building

Stated up front so it can be checked rather than discovered late:

- **If the fleet turns out to be small and homogeneous,** managed settings plus the
  sandbox plus `disableBypassPermissionsMode` — M0's configuration work with none
  of its software — may cover most of the realistic risk. Check this at M0 exit:
  if the observed traffic shows the sandbox already blocking the paths we are
  worried about, the remaining milestones are lower value than they look.
- **If the false-positive rates at M2 are bad enough,** the R2 gate may never be
  promotable, and the honest outcome is a detection-and-review system with no
  enforcement. That is still worth having; it is just a different product than the
  one M3 describes.
- **If Anthropic ships fleet-level agent monitoring,** M0/M1 become redundant and
  the differentiated work is M2/M4 — provenance and goal drift — which is where the
  actual research insight lives anyway. Worth tracking.
