# 03 — Detection

Three layers, in increasing order of cleverness and decreasing order of
reliability. Deploy in that order, and never let a lower-reliability layer block a
tool call inline.

1. **Deterministic** — Rule-of-Two accounting, credential-path access, egress,
   config drift, MCP metadata drift, session-shape rules. Cheap, explainable,
   suitable for gating.
2. **Provenance** — did this action derive from untrusted content. Heuristic but
   structural. Suitable for gating on high-impact action classes.
3. **Semantic** — does this action serve the stated objective. Highest value
   against covert side tasks, least reliable. Advisory and aggregate only.

## Where each detector lives

The split follows from [02](02-architecture.md): anything needing live session
state or an inline verdict is `agentd`; anything that is cross-event or
cross-endpoint correlation is a Wazuh rule.

| Detector | Verdict computed in | Alert raised by | Why there |
| --- | --- | --- | --- |
| R2 gate | **agentd** | agentd emits verdict; Wazuh alerts on it | Needs live per-session bits; must return inline |
| Provenance edge | **agentd** | agentd emits edge; Wazuh alerts on it | Needs the session's fingerprint set in memory |
| D1 session with no human | **agentd** (shape) | Wazuh rule | Single-event fields, but worth a manager-side rule for fleet view |
| D2 credential sweep | **Wazuh rule** | Wazuh | `frequency` + `timeframe` does this natively |
| D3 bypass attempt | agentd emits | Wazuh rule | Single event, level-16 alert |
| D4 MCP metadata drift | **mcp-interpose** | Wazuh rule | Hash comparison needs the local baseline |
| D5 instruction-shaped description | **mcp-interpose** | Wazuh rule | Text scan at `tools/list` time |
| D6 config tamper | **Wazuh FIM** + agentd `ConfigChange` | Wazuh | Native syscheck; neither half sufficient alone |
| D7 telemetry gap | **Wazuh** | Wazuh rule 504 + absence rule | Native agent-disconnect; absence rule for the finer half |
| D8 poisoned instruction file | agentd emits | Wazuh rule | From `InstructionsLoaded` |
| D9 egress anomaly | agentd + sandbox denials | Wazuh rule | Baselining is cross-event |
| D10 cross-session propagation | **Wazuh rule** (partial) | Wazuh | See [the D10 investigation](#d10-can-wazuh-rules-do-cross-session-propagation) |
| D11 fail-open run | agentd emits | **Wazuh rule** | `frequency` + `timeframe` |
| D12 managed-settings drift | **Wazuh SCA** | Wazuh | Policy-as-YAML, native |
| Goal drift | **agentd**, async | Wazuh rule on score | Needs the declared objective and action history |

## Layer 1 — Rule-of-Two accounting

Meta's Agents Rule of Two (31 October 2025) states that until prompt injection can
be reliably detected and refused, an agent should satisfy **no more than two of
three properties within a session**: processing untrusted input, accessing
sensitive data, and changing state or communicating externally. An agent needing
all three without a fresh context window should not operate autonomously and
requires at minimum human-in-the-loop supervision.

Everything needed is in the hook stream. Nobody tracks it. Lives in `agentd`
because the bits are live session state and the gate must return inline.

Three bits per session, monotonically set (never cleared within a session — see
[07](07-open-questions.md) Q1).

**Bit A — untrusted input ingested.** Set by:
- `WebFetch` / `WebSearch` result from a domain not on the trusted-content list
- Bash output from a command that made a network request
- An MCP tool result from a server whose trust label is not `internal`, or any tool
  annotated `openWorldHint: true`
- `InstructionsLoaded` for a `CLAUDE.md` or `.claude/rules/*.md` under a path not on
  the trusted-repo list
- A `Read` of a file in an untrusted zone: `node_modules/`, vendored dependencies,
  `~/Downloads`, anything git reports as untracked-and-recently-created
- Issue / PR / ticket / email bodies arriving through any MCP tool

**Bit B — sensitive data accessed.** Set by:
- Read of a credential path: `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`,
  `**/.env*`, `.npmrc`, `.netrc`, `**/id_*`, keystores, wallet files
- Read of a file whose content trips the edge secrets classifier
- Read outside the session's working-directory boundary
- An MCP tool returning data from a system labelled sensitive

**Bit C — state change or external communication.** Set by:
- Bash command with network capability (`curl`, `wget`, `nc`, `ssh`, `scp`,
  `git push`, package publish)
- `Write` / `Edit` outside the working directory
- An MCP tool that is not `readOnlyHint: true` — and per
  [02](02-architecture.md)'s asymmetry, a server *claiming* read-only earns no
  relaxation, so in practice treat every MCP tool on a non-internal server as
  C-setting unless an operator has explicitly classified it
- Git push, PR creation, package publish, any outbound API write

**The gate**, in `agentd`, on `PreToolUse`:

| Action class | Third-bit policy |
| --- | --- |
| Credential-path read after A | `deny` |
| Outbound network from Bash after A and B | `deny` |
| `git push` / publish after A and B | `ask` |
| Write outside working dir after A and B | `ask` |
| MCP non-read-only tool after A and B | `ask` |
| Everything else | `allow` + alert |

Start all of these at `ask` or `allow`+alert and promote to `deny` only with
baseline data ([05](05-build-plan.md)).

**Honest limitation.** The rule is stated over a session, and "session" is doing
real work in that sentence. Compaction, `/clear`, subagents, and long-running
sessions all make the boundary ambiguous, and a monotonic bit over an 8-hour session
saturates to all-three and gates everything. Biggest open design problem in the
system; [07](07-open-questions.md) Q1.

## Layer 2 — Provenance

Link "untrusted content entered here" to "this action happened." CaMeL (*Defeating
Prompt Injections by Design*, arXiv:2503.18813) does this soundly with a custom
interpreter tracking a dataflow graph over every variable, a privileged LLM that
never touches untrusted data, and a quarantined LLM with no tool access — 77% of
AgentDojo tasks with provable security.

**We cannot do that.** CaMeL requires control of the interpreter and the agent
loop; Claude Code is a black box emitting events. This layer is an explicitly
unsound approximation, and the design says so rather than implying taint-tracking
guarantees it does not have.

### 2a — Session taint (sound, coarse)

Bit A as a label. Reliable, useless alone for attributing a *specific* action.

### 2b — Content fingerprinting (unsound, specific)

At every untrusted ingest, extract and store fingerprints:

- Registrable domains and full URLs
- Email addresses
- High-entropy tokens (≥ 20 chars, entropy above threshold)
- IP addresses and host:port pairs
- Rare n-grams: shingles below a corpus-frequency threshold

On every `PreToolUse`, extract the same classes from `tool_input` and intersect with
the session's ingest fingerprints. A hit yields a **provenance edge**:
`action ← ingest`, with the matched token class as evidence.

**The intersection runs in `agentd`, in memory, and only the resulting edge is
emitted.** This is not negotiable for two reasons: the fingerprint set is live
session state, and shipping every fingerprint of every ingest to the SIEM would be
the firehose [04](04-data-model.md) exists to prevent.

Catches the canonical exfiltration: the attacker's domain, webhook URL, or email
appears in injected content and then in a `curl` argument or a `Write`. Evidence is
concrete and human-reviewable, which matters for a gate.

Failure modes, both directions:
- **False negatives from paraphrase.** The model re-wording the instruction, or
  reconstructing the destination from memory, defeats it entirely. Edge lost;
  session taint remains.
- **False positives from legitimate carry-through.** An agent asked to summarize a
  page and write the summary legitimately carries content across. Domain and
  high-entropy matches are far more specific than n-gram matches; weight
  accordingly and treat n-gram matches as advisory.

### 2c — Causal ordering

Using `prompt_id` and `sequence`, detect *first occurrence after ingest*: within a
prompt turn, an action class the session has not exhibited before, after an
untrusted ingest. First credential read, first outbound connection, first write
outside the working directory.

Weak alone. Valuable as a multiplier on 2a: "session tainted, then did something it
had never done in 400 prior turns" beats either half.

## Layer 3 — Goal drift

The direct answer to the covert-side-task finding, and the reason to build any of
this.

SHADE-Arena (Kutasov et al., arXiv:2506.15740; Anthropic with Redwood Research,
Scale AI and others, June 2025) places an agent in a simulated workplace with a
benign main task plus a hidden malicious side task, scored by a monitor blind to the
side task. The finding that matters: side-task success depended heavily on the model
having a hidden scratchpad the monitor could not see, and follow-ups consistently
report that **monitors watching actions caught covert side tasks far more reliably
than monitors watching only reasoning.** Anthropic's Claude Opus 4.6 Sabotage Risk
Report (February 2026) reports ~18% side-task success under monitoring with thinking
available, ~16% without *(vendor-reported; not independently replicated)*.

Reasoning-level monitoring is fragile. Action-level monitoring is durable. So:

**Does this action serve the objective the user actually stated?**

- `UserPromptSubmit` gives `user_input` — the declared objective, verbatim, before
  the model has touched it.
- Each subsequent tool call is scored for relevance by a small cheap model, given
  the objective, the action, and a compact session summary.
- Scoring runs **asynchronously in `agentd`**. It never gates a `PreToolUse`: too
  slow for a 5 ms budget and too unreliable to block a developer's file read.
- The score is emitted as an event; Wazuh rules alert on sustained drift, and on the
  composite condition below.

Page condition: an action scored strongly unrelated **and** carrying a provenance
edge **and** setting a Rule-of-Two third bit. Any one alone is noise.

What this buys that nothing else does: it catches the case where every individual
action is permitted — GTG-1002's decomposition, where each step is defensible in
isolation — and it needs no knowledge of the attack, only of the task.

Be clear-eyed: an LLM judge is itself promptable, so **the scorer never sees raw
untrusted content**, only structured action descriptions, and its prompt is a
security boundary. And "unrelated to the stated objective" describes a great deal of
legitimate engineering — reading unrelated files to understand a codebase, fixing an
unrelated broken test. Expect noise; budget for tuning.

## Wazuh rules

Custom rules live at ID ≥ 100000 (rule IDs range 1–999999; custom rules
conventionally above 100000). Every rule carries a `<mitre>` block and a `<group>`
naming its runbook.

### Rule syntax facts this design relies on

All verified against the 4.x ruleset documentation and the shipped ruleset:

- `frequency`: "Number of times the rule must match before generating an alert,"
  allowed 2–9999, triggering at that many matches **or more** within the timeframe.
- `timeframe`: seconds, 1–99999.
- `if_matched_sid`: like `if_sid` but only matches if that rule ID triggered within
  a period of time — the compositional primitive for "N of these, then that."
- `same_field`: "The value of the dynamic field specified in this option must appear
  a certain number of times in previous events, as defined by the `frequency`
  attribute, within a time frame specified by the `timeframe` attribute." Documented
  as working on **dynamic** fields (what the JSON decoder produces) and explicitly
  **not** on static fields — which is exactly our case.
- `ignore="N"`: rule attribute suppressing repeat alerts for N seconds. Used in the
  shipped ruleset (e.g. rule 80443) and necessary to stop a noisy detector
  self-DoSing the review queue.

### D2 — credential sweep, as frequency + timeframe

```xml
<group name="ipctl,ipctl_credential,">
  <!-- Base: agentd reported a credential-zone read. -->
  <rule id="100210" level="5">
    <decoded_as>json</decoded_as>
    <field name="kind">^tool_pre$</field>
    <field name="path_zone">^credential$</field>
    <field name="path_op">^read$</field>
    <description>ipctl: credential-zone read by $(agent_kind) session $(session_id)</description>
    <mitre>
      <id>T1552.001</id>
    </mitre>
    <group>ipctl_d2,runbook_D2,</group>
  </rule>

  <!-- D2: many of them, same session, short window. -->
  <rule id="100211" level="12" frequency="8" timeframe="120" ignore="300">
    <if_matched_sid>100210</if_matched_sid>
    <same_field>session_id</same_field>
    <description>ipctl D2: credential sweep - 8+ credential-zone reads in one session within 120s</description>
    <mitre>
      <id>T1552.001</id>
      <id>T1555</id>
    </mitre>
    <group>ipctl_d2,runbook_D2,</group>
  </rule>
</group>
```

`same_field` on `session_id` is what makes this a *sweep by one agent* rather than
eight unrelated reads across the fleet. Thresholds are placeholders to be set from
M2 baseline data, not from intuition — a repo with forty `.env` files in a monorepo
will trip 8-in-120s during an ordinary build.

### D11 — fail-open run, same shape

```xml
<group name="ipctl,ipctl_integrity,">
  <rule id="100260" level="5">
    <decoded_as>json</decoded_as>
    <field name="policy_decision">^fail_open$</field>
    <description>ipctl: agentd unavailable, tool call failed open on $(endpoint_id)</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>ipctl_d11,runbook_D11,</group>
  </rule>

  <rule id="100261" level="12" frequency="5" timeframe="300" ignore="600">
    <if_matched_sid>100260</if_matched_sid>
    <same_field>endpoint_id</same_field>
    <description>ipctl D11: sustained fail-open - agentd repeatedly unavailable on one endpoint</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>ipctl_d11,runbook_D11,</group>
  </rule>
</group>
```

### D7's finer half — absence of the agentd stream

Rule 504 covers the endpoint going dark. The harder case is the Wazuh agent alive
while `agentd` is dead: the endpoint heartbeats, FIM and SCA keep reporting, and only
the `agentd` event stream stops.

Wazuh rules fire on events, not on their absence, so this is not expressible as a
correlation rule. Two options, and the second is better:

1. `agentd` emits a periodic `agentd_health` heartbeat event; a scheduled query on
   the indexer flags endpoints with no heartbeat in N minutes. Requires something
   outside the rule engine to run the query.
2. **The Wazuh agent reports on `agentd`'s liveness rather than `agentd` reporting on
   its own.** SCA check 10005 (`p:agentd`) already runs on the Wazuh agent's
   schedule and fails when the process is gone. A failed SCA check is an event, so
   this needs no external scheduler and — critically — the signal comes from a
   *different process than the one being watched*, which is the whole point when the
   adversary can kill processes.

Recommendation: option 2 as primary, with option 1's heartbeat retained because
`p:agentd` cannot tell a wedged daemon from a healthy one. Combined, a wedged
`agentd` shows as "process present, heartbeat stale."

### D12 — managed-settings drift (new)

SCA policy from [02](02-architecture.md). A failed check raises an SCA alert
natively; the custom rule raises severity and attaches the runbook:

```xml
<group name="ipctl,ipctl_integrity,">
  <rule id="100270" level="12">
    <if_sid>19007</if_sid>
    <field name="sca.policy_id">^ipctl_managed_settings$</field>
    <description>ipctl D12: managed-settings assertion failed - $(sca.check.title) on $(agent.name)</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>ipctl_d12,runbook_D12,</group>
  </rule>
</group>
```

The parent SID and the exact `sca.*` field names must be confirmed against the
deployed Wazuh version's SCA ruleset before this rule works — **unverified here**;
the SCA alert rule IDs were not checked against the shipped ruleset during research.
Treat this snippet as the intended shape, not working configuration.

### D10 — can Wazuh rules do cross-session propagation?

Investigated as asked. The answer is **partially, and only in a degenerate form.**

`same_field` does correlate on a shared dynamic-field value across events within a
timeframe — the shipped ruleset uses exactly this pattern (rule 80443:
`frequency="8" timeframe="120"`, `if_matched_sid`, `same_field`
`aws.httpRequest.clientIp`). So a rule of this shape is expressible:

```xml
<!-- D10 (partial): the same notable fingerprint seen twice, in different sessions. -->
<rule id="100280" level="12" frequency="2" timeframe="3600" ignore="600">
  <if_matched_sid>100279</if_matched_sid>
  <same_field>prov_fp_notable</same_field>
  <description>ipctl D10: fingerprint $(prov_fp_notable) seen in two sessions - possible cross-agent propagation</description>
  <mitre>
    <id>T1105</id>
  </mitre>
  <group>ipctl_d10,runbook_D10,</group>
</rule>
```

Three limitations, and they are structural rather than tuning problems:

1. **`same_field` is scalar equality, and D10 is a set intersection.** An ingest
   yields hundreds of fingerprints; an output yields hundreds. D10 asks whether the
   two sets intersect. Rule syntax cannot express that, and Wazuh's JSON decoder
   does not support an array of objects ([04](04-data-model.md)), so the sets cannot
   even be represented usefully in the event.
2. **"Different session" is not expressible alongside "same fingerprint."**
   `same_field` takes one field name. Whether `<same_field>prov_fp_notable</same_field>`
   and `<different_field>session_id</different_field>` compose is **unverified** —
   the docs describe each independently and the shipped ruleset does not use them
   together. Without it, the rule also fires on one session that ingests and then
   re-emits the same fingerprint, which is ordinary behavior, not propagation.
3. **Direction is lost.** D10 means "ingest in X, output in Y." The rule sees two
   occurrences of a value and cannot order them by role without separate parent
   SIDs for ingest and output, which doubles the rule count and still does not fix
   (1).

**Resolution.** Split it:

- `agentd` pre-selects, per event, at most one **notable fingerprint** — from the
  high-specificity classes only (domain, email, high-entropy token) — and emits it
  as the scalar field `prov_fp_notable`, with `prov_fp_role` of `ingest` or `output`.
  The Wazuh rule above then works as a cheap first-pass tripwire on high-value
  fingerprints.
- The **full set intersection stays out of the SIEM.** Cross-session set matching
  runs as a scheduled job over the indexer's feature columns, or locally over the
  spool. This is the honest version of D10 and it is not a rule.

So D10 is a Wazuh rule for the scalar tripwire case and code for the real case. It
lands in M5 either way, and the scalar tripwire is worth having in M1 because it is
nearly free.

### Proposed MITRE ATT&CK mappings

External firms will expect technique IDs on every alert. These are **proposals for
review by whoever owns detection engineering**, not authoritative mappings — several
are approximations, because ATT&CK has no techniques that specifically describe
agent hijacking or covert side tasks.

| Detector | Technique(s) | Note |
| --- | --- | --- |
| D1 session with no human | T1059 | Command and Scripting Interpreter |
| D2 credential sweep | T1552.001, T1552.004, T1555 | Credentials in Files, Private Keys, from Password Stores |
| D3 bypass attempt | T1562.001 | Impair Defenses |
| D4 MCP metadata drift | T1195.002 | Compromise Software Supply Chain |
| D5 poisoned tool description | T1195.002 | Closest available; the injection aspect has no technique |
| D6 config tamper | T1562.001 | |
| D7 telemetry gap | T1562.001 | Matches shipped rule 504's own tag |
| D8 poisoned instruction file | T1195.002, T1546 | Event Triggered Execution |
| D9 egress anomaly | T1041, T1567 | Exfiltration Over C2 Channel / Web Service |
| D10 propagation | T1105, T1570 | Ingress Tool Transfer / Lateral Tool Transfer |
| D11 fail-open run | T1562.001 | |
| D12 managed-settings drift | T1562.001 | |
| R2 gate (deny) | T1552, T1041 | Depends which third bit tripped |
| Goal drift | — | **No good mapping.** Stated as a gap rather than forced into T1059. |

That last row matters: forcing a bad mapping to satisfy a reporting expectation
makes the alert harder to triage, not easier. Better to ship it untagged and say why.

## Detector catalogue

| # | Detector | Signal |
| --- | --- | --- |
| D1 | **Session with no human.** Non-interactive entrypoint, `permission_mode` = `bypassPermissions`, `SessionStart` with no `UserPromptSubmit`, immediate credential reads. | The s1ngularity signature. Highest-confidence detector in the system. |
| D2 | **Credential sweep.** N credential-path reads in a short window across unrelated directories. | Staging for exfiltration |
| D3 | **Bypass attempt.** Invocation with `--dangerously-skip-permissions` / `--yolo` / `--trust-all-tools`, or `bypassPermissions` where managed policy disables it. | Active attack or serious policy violation |
| D4 | **MCP metadata drift.** Tool name / description / schema hash differs from approved baseline. | Rug pull |
| D5 | **Instruction-shaped tool description.** Imperative language, role assertions, or references to other servers' tools. | Tool poisoning / shadowing |
| D6 | **Config tamper.** FIM on `.claude/` and `.mcp.json` (with `whodata`), plus `ConfigChange`. | Suppression attempt |
| D7 | **Telemetry gap.** Rule 504 for endpoint silence; SCA `p:agentd` plus stale heartbeat for daemon death. | Daemon suppression |
| D8 | **Poisoned instruction file.** `InstructionsLoaded` under a newly cloned or untrusted path. | Repo-carried injection |
| D9 | **Egress anomaly.** Outbound volume or destination outside the endpoint's profile; any sandbox allowlist denial. | Exfiltration |
| D10 | **Cross-agent fingerprint match.** Scalar tripwire as a rule; full set intersection as a scheduled job. | Prompt Infection / propagation |
| D11 | **Fail-open run.** Repeated `agentd` unavailability. | Suppression |
| D12 | **Managed-settings drift.** SCA assertion failure on the bundle. | Suppression / misconfiguration |

## Runbooks

Every rule carries a `runbook_Dn` group. **Each runbook must be written for an
analyst who cannot see our source tree** ([01](01-threat-model.md)): paths arrive as
keyed digests, and only zone labels (`credential`, `workdir`, `untrusted`, `system`)
are in cleartext. A runbook that says "check whether the file is sensitive" is
useless to them; one that says "the zone label already asserts this is a credential
path, so proceed to step 2" works.

Each runbook states, in this order:

1. **What the alert asserts**, in terms of fields present in the alert only.
2. **What it does not assert** — the detector's known false-positive modes, named.
   For D2: a monorepo with many `.env` files during a build.
3. **Triage steps executable with the alert alone**: which fields to read, which
   correlate to pull (`session_id`, `endpoint_id`, `prompt_id`), what a benign
   pattern looks like versus a malicious one.
4. **What requires us.** Digest resolution, spool pull, local content — with the
   request path and expected turnaround. This is the step that keeps an
   external analyst productive without cleartext paths, and it has to be a real
   process with an SLA, not a note saying "ask the customer."
5. **Containment**, if any, and who executes it. For D1 and D3: credential
   revocation, executed by us, not by the MSSP ([02](02-architecture.md)).
6. **Escalation threshold** — when to page rather than queue.

Runbooks are the deliverable that makes external monitoring work, and they are
easy to under-invest in. A detector without a runbook an outsider can execute is a
detector that generates tickets nobody can close.

## Validating the detectors

Detectors need adversarial tests, and building our own corpus would be the wrong use
of time when three public ones exist:

- **AgentDojo** (ETH Zurich) — indirect prompt injection / agent hijacking. NIST
  CAISI used it to show attack success rising from 11% for the strongest baseline
  attack to 81% for a stronger adaptive attack on Claude 3.5 Sonnet — the empirical
  reason not to rely on injection *detection*.
- **SHADE-Arena** — the covert-side-task format layer 3 is built to catch.
- **ControlArena** (UK AISI with Redwood Research) — control protocols, settings,
  model organisms.

Use as the regression suite: replay trajectories through `agentd`, measure detection
and false-positive rate per detector. Wazuh rules get their own test path —
`wazuh-logtest` takes a log line and reports which decoder and rule matched, so rule
correctness is testable from a fixture file of `events.jsonl` lines without a live
fleet.

NIST's finding carries a methodological warning worth adopting: **evaluate against
attacks adapted to our detectors, not only generic baselines.** A detector tuned on
baseline attacks overstates its own coverage.
