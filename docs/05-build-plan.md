# 05 — Build plan

## The sequencing argument

Observe before enforce, and mean it.

A `PreToolUse` hook returning `deny` sits in the critical path of every tool call on
every endpoint. A false deny does not degrade gracefully — it stops a developer
mid-task, with a confusing reason, fleet-wide and simultaneously. Two or three of
those and the managed settings get an exception carved out, and the system is over.

There is also no way to tune a threshold without a baseline. "Reads a credential path
after fetching a web page" sounds obviously bad until you learn the team's deploy
script does exactly that forty times a day. Every detector in
[03](03-detection.md) needs its false-positive rate measured against real traffic
before it gates anything.

M0 and M1 ship with no ability to block. Enforcement begins at M3, starts at `ask`
rather than `deny`, and is promoted per-rule on evidence.

## What adopting Wazuh deletes

Before the milestones: the pre-Wazuh plan had M0 building "ingest, append-only store,
columnar analytics, enrollment, heartbeat" and a dashboard. Almost all of that is now
deployment and configuration rather than software.

**Deleted outright:**

- Ingest service and its API — replaced by `events.jsonl` plus the Wazuh agent's
  `localfile` tail. No custom decoder either, since the built-in JSON decoder
  produces addressable dynamic fields.
- Append-only event store and retention machinery — Wazuh indexer.
- Columnar analytics layer for detector queries — Wazuh rules for the correlation
  detectors; a scheduled job over object storage for the two that need set
  operations.
- Enrollment and endpoint roster — Wazuh agent registration.
- Heartbeat and agent-liveness tracking — native, and **D7's coarse half arrives for
  free**: rule 504, `Wazuh agent disconnected`, level 3, already tagged MITRE
  T1562.001 in the shipped ruleset.
- Alerting, alert routing, severity model, and the review-queue UI — Wazuh manager
  plus dashboard, with RBAC for external access.
- MITRE ATT&CK tagging infrastructure — `<mitre>` block per rule.
- Most of D6 — FIM/syscheck with `whodata` on `.claude/` and `.mcp.json`.

**Added by the change:**

- The SIEM-bound flattened schema and the mapping in [04](04-data-model.md), which is
  new work that did not exist when we owned both ends.
- The `ambitd`-side filter deciding what crosses ([04](04-data-model.md)) — new, and
  load-bearing: get it wrong and either the indexer drowns or detection goes blind.
- Wazuh rules, one set per detector, each with a runbook written for an analyst who
  cannot see our source tree.
- SCA policy asserting the managed-settings bundle (D12) — genuinely new capability,
  not a port. The managed-settings anchor was previously assumed; now it is verified.
- Wazuh deployment and operation: manager sizing, indexer retention, RBAC, agent
  groups, tenancy ([07](07-open-questions.md) Q11).
- Active-response allowlisting on the endpoint, because the manager can now command
  endpoints ([02](02-architecture.md)).

**Net:** M0 shrinks a lot — from building a platform to deploying one and writing the
endpoint half. M1 grows slightly, because rules and runbooks are now the unit of
detection work. The unchanged core is `ambitd`: the R2 accounting, the provenance
intersection, and the gate, which is where the design's actual contribution lives and
which Wazuh cannot do.

## M0 — Observe

**Goal:** answer "what did all our agents do yesterday," and nothing more.

- **Deploy Wazuh**: manager, indexer, dashboard. Agent enrolled on the cohort
  endpoints. `logall` and `logall_json` left at `no`.
- `ambitd`: HTTP hook endpoint on localhost, OTLP/HTTP receiver on 4318
  (`http/json` only — see [02](02-architecture.md) on why not grpc or protobuf),
  local spool, `events.jsonl` writer. **No policy engine** — every hook response
  is empty.
- Stream-discrepancy counters across the hook and OTel paths, feeding
  `ambitd_health`. This is D7's third signal and the reason the OTel receiver is
  in M0 at all rather than deferred: without a second path there is nothing to
  corroborate against.
- Normalized internal schema v2 and the flattened SIEM-bound schema
  ([04](04-data-model.md)), edge redaction, keyed feature extraction, the
  crosses-to-Wazuh filter.
- `localfile` config tailing `events.jsonl` with `log_format json`. Confirm dynamic
  fields are addressable with `wazuh-logtest` against fixture lines.
- FIM on `.claude/` and `.mcp.json` with `whodata` — watching directories with
  `restrict`, since realtime does not work on individual files.
- Managed settings bundle: hooks for observation events, OTel enabled and
  destination-pinned. **No permission changes, no sandbox changes.**
- One dashboard: sessions, tool-call volume, MCP servers in use, permission modes,
  entrypoints.

**Exit criteria:**

- Deployed to a volunteer cohort (5–10 endpoints).
- p99 hook response under 5 ms.
- Zero developer-visible behavior change — verified by asking them, not assuming.
- Event loss under 0.1% on the local spool.
- **The interesting fraction is measured.** [04](04-data-model.md) estimates 2–5% of
  tool calls cross to Wazuh. If it comes back materially higher, the criteria tighten
  or sampling drops before M1. No detector work starts on an unmeasured firehose.
- No `Too many fields for JSON decoder` errors in the manager log, and the actual
  field count per event kind recorded against the `decoder_order_size` limit.

**Deliberately not in M0:** any decision, any alert, any blocking. If M0 changes one
thing about how a developer's session behaves, it has failed.

## M1 — Inventory, drift, and the first rules

**Goal:** know what MCP surface the fleet trusts, notice when it changes, and get the
cheap high-confidence detectors alerting.

- `mcp-interpose`: wraps configured servers, captures `tools/list`, hashes name +
  description + schema per tool, records annotations, labels results. **Build-vs-adopt
  is decided — purpose-built, in Go, per server** ([08](08-mcp-interpose-decision.md)).
  **Built and tested**: D4's baseline with an explicit approval step, D5's metadata
  scan, annotation carriage, and `mcp_list` emission through `ambitd`, with the
  interposer inert by construction (byte-exact passthrough, no verdict, degrades to
  passthrough on every failure). Still open: the Wazuh rules and runbooks that read
  these events, and HTTP/SSE servers, which a stdio wrapper does not cover and which
  M0's stream tells us whether the cohort uses.
- Approval baseline: first-seen metadata hash per server/tool, with an explicit
  operator approval step.
- **SCA policy for the managed-settings bundle (D12)** — and confirm the SCA alert
  parent SID and `sca.*` field names against the deployed version, which
  [03](03-detection.md) flags as unverified.
- Wazuh rules for D4, D5, D6, D7, D8, D11, D12, plus D10's scalar
  `prov_fp_notable` tripwire — nearly free once the field exists.
  **D4 and D5 are written** (`deploy/wazuh/rules/ambit_mcp_rules.xml`, IDs
  100230–100248), validated offline against fixtures generated from the real pipeline,
  and still need one confirmation on a live manager: how a `<field>` regex matches an
  array-valued field ([00](00-sources.md)). D6, D7, D8, D11, D12 and D10's tripwire
  remain.
- Runbooks for each, written for an external analyst. **D4 and D5 are written**
  (`deploy/wazuh/runbooks/`); the exit criterion that someone outside the team executes
  one against a sample alert is still open, and it is the half that actually tests them.
- Alerting to the Wazuh review queue. **Still no blocking.**

**Exit criteria:** every MCP server the cohort uses is inventoried with an approved
baseline. A deliberately mutated test server triggers D4 within one session. Killing
`ambitd` on a test endpoint fires D7 via SCA `p:ambitd`; stopping the Wazuh agent
fires rule 504. Reverting a managed-settings key fires D12. Every rule has a runbook
a person outside the team can execute against a sample alert — tested by having
someone outside the team do it.

**Why before provenance:** cheapest real security value in the plan. Rug-pull and
tool-poisoning detection is a hash comparison and a regex with a naturally near-zero
false-positive rate, and it covers adversary A3 outright. Provenance is more
interesting and much more work.

## M2 — Provenance and Rule-of-Two, alert only

**Goal:** produce the signals that later gate, and measure how noisy they are.

- Provenance engine in `ambitd`: session taint, content fingerprinting, causal
  ordering. Intersection local; edges and the notable fingerprint emitted.
- Rule-of-Two accounting: the three bits and the zone/annotation classification
  tables.
- Every gate from [03](03-detection.md) evaluated and **recorded as the decision it
  would have made** — shadow mode. `policy_decision` carries the shadow verdict; no
  decision returned to Claude Code.
- Wazuh rules for D1, D2, D3, D9, and for shadow-verdict volume by rule.
- Replay harness: AgentDojo, SHADE-Arena, ControlArena trajectories through `ambitd`;
  per-detector detection and false-positive rates. Rule correctness tested separately
  with `wazuh-logtest` over fixture `events.jsonl` lines.

**Exit criteria:** the shadow-mode report shows, per rule, how many times it would
have blocked and a human-reviewed verdict on each. **A rule does not advance to M3
until its would-have-blocked set is reviewed and its false-positive rate is
acceptable for its action class.** Session-boundary behavior (compaction, `/clear`,
long sessions, subagents) is measured, answering [07](07-open-questions.md) Q1 with
data rather than argument.

This is the milestone most likely to reveal a detector is unusable. That is the point
of it.

## M3 — Enforce

**Goal:** actually stop things, without becoming the reason the project gets switched
off.

- Policy engine returns real decisions. Signed policy bundles, version-pinned,
  `ambitd` refusing unsigned or downgraded bundles — **delivered over a path separate
  from Wazuh's centralized configuration** ([02](02-architecture.md)), so manager
  access does not confer the ability to rewrite the gate.
- Split fail policy: narrow fail-closed set, fail-open plus record otherwise. Per
  [07](07-open-questions.md) Q7, fail-closed means `ask`.
- Managed settings tighten: `disableBypassPermissionsMode`, sandbox
  `failIfUnavailable`, `allowManagedDomainsOnly` with a curated allowlist. D12 now
  asserts each of these, so tightening and verification land together.
- Active response, containment only: credential revocation on D1/D3. Endpoint-side
  allowlist of permitted scripts; the manager names a command, never ships one.
- **Promotion ladder per rule:** shadow → `ask` → `deny`. Minimum two weeks at `ask`
  with a reviewed false-positive rate before `deny`.
- Developer-facing escape hatch: a block names the rule, gives a specific reason, and
  has a fast exception path. A gate with no appeal gets circumvented.

**Exit criteria:** fail-closed set enumerated and justified. Documented rollback: one
bundle version revert, plus a kill switch returning `ambitd` to observe-only without
touching managed settings. Active-response allowlist reviewed, and MSSP roles
confirmed to hold no dispatch permission.

## M4 — Goal drift

**Goal:** catch the covert side task — the thing the research is about.

- Objective capture from `UserPromptSubmit`.
- Async scoring of actions against the declared objective by a small model, over
  structured action descriptions only. **The scorer never sees raw untrusted
  content** — it is an LLM in the security path and therefore itself an injection
  target.
- Only above-threshold scores cross to Wazuh ([04](04-data-model.md)); all scores
  stay in the spool.
- Wazuh rule on the composite page condition: strongly unrelated action **and** a
  provenance edge **and** an R2 third bit.
- Measured against SHADE-Arena.

**Exit criteria:** measured detection rate on SHADE-Arena-style covert side tasks, and
a false-positive rate against real cohort traffic a human review queue can absorb. If
the queue is unworkable, the composite condition tightens rather than the detector
shipping as a gate. Per [07](07-open-questions.md) Q6, the cost pre-filter is decided
here.

Stays advisory. It does not gate inline, and promoting it later requires a separate
argument.

## M5 — Fleet correlation

**Goal:** the multi-agent problems.

- D10's real form: cross-session fingerprint **set intersection** as a scheduled job
  over object storage or indexer feature columns. The scalar tripwire from M1 stays as
  the cheap first pass; [03](03-detection.md) explains why the set version cannot be a
  rule.
- Session-shape analysis for A4: decomposition patterns across sessions and operators,
  aggregate review rather than per-action blocking.
- Per-endpoint and per-user behavioral baselines for D9.

**Exit criteria:** a seeded propagation test — inject a fingerprint into one session's
ingest, have it surface in a second session — is detected by the scheduled job, and
the M1 tripwire's hit rate against it is measured (it will miss cases; how many
matters).

## Dependencies

```
M0 (deploy Wazuh + observe) ──► M1 (inventory, drift, first rules) ──► M3 (enforce)
     │                                                                  ▲
     └──────────────────────► M2 (provenance / R2, shadow) ─────────────┘
                                    │
                                    ├──► M4 (goal drift)
                                    └──► M5 (fleet correlation)
```

M1 and M2 are independent after M0 and can run in parallel. M3 requires both. M4 and
M5 require M2's provenance layer. [07](07-open-questions.md) Q11 (tenancy) blocks MSSP
onboarding, not M0 — deploy single-tenant first and add the tenancy model before any
external party gets access.

## What could make this not worth building

Stated up front so it can be checked rather than discovered late:

- **If the fleet is small and homogeneous,** managed settings plus the sandbox plus
  `disableBypassPermissionsMode` — M0's configuration work with none of its software —
  may cover most of the realistic risk. Check at M0 exit: if observed traffic shows
  the sandbox already blocking the paths we worry about, the later milestones are
  lower value than they look.
- **If M2's false-positive rates are bad enough,** the R2 gate may never be
  promotable, and the honest outcome is detection-and-review with no enforcement.
  Still worth having; just a different product than M3 describes.
- **If Anthropic ships fleet-level agent monitoring,** M0/M1 become largely redundant
  and the differentiated work is M2/M4 — provenance and goal drift — which is where
  the research insight lives anyway.
- **If the Wazuh 5.0 migration is disruptive enough** ([07](07-open-questions.md)
  Q12), the rules written in M1–M2 carry a rewrite cost. That changes the schedule,
  not the design, but it should be priced before the rule count gets large.
