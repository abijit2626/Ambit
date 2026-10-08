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
state or an inline verdict is `ambitd`; anything that is cross-event or
cross-endpoint correlation is a Wazuh rule.

| Detector | Verdict computed in | Alert raised by | Why there |
| --- | --- | --- | --- |
| R2 gate | **ambitd** | ambitd emits verdict; Wazuh alerts on it | Needs live per-session bits; must return inline |
| Provenance edge | **ambitd** | ambitd emits edge; Wazuh alerts on it | Needs the session's fingerprint set in memory |
| D1 session with no human | **ambitd** (shape) | Wazuh rule | Single-event fields, but worth a manager-side rule for fleet view |
| D2 credential sweep | **Wazuh rule** | Wazuh | `frequency` + `timeframe` does this natively |
| D3 bypass attempt | ambitd emits | Wazuh rule | Single event, level-16 alert |
| D4 MCP metadata drift | **mcp-interpose** | Wazuh rule | Hash comparison needs the local baseline |
| D5 instruction-shaped description | **mcp-interpose** | Wazuh rule | Text scan at `tools/list` time |
| D6 config tamper | **Wazuh FIM** + ambitd `ConfigChange` | Wazuh | Native syscheck; neither half sufficient alone |
| D7 telemetry gap | **Wazuh** | Wazuh rule 504 + absence rule | Native agent-disconnect; absence rule for the finer half |
| D8 poisoned instruction file | ambitd emits | Wazuh rule | From `InstructionsLoaded` |
| D9 egress anomaly | ambitd + sandbox denials | Wazuh rule | Baselining is cross-event |
| D10 cross-session propagation | **Wazuh rule** (partial) | Wazuh | See [the D10 investigation](#d10--can-wazuh-rules-do-cross-session-propagation) |
| D11 fail-open run | ambitd emits | **Wazuh rule** | `frequency` + `timeframe` |
| D12 managed-settings drift | **Wazuh SCA** | Wazuh | Policy-as-YAML, native |
| Goal drift | **ambitd**, async | Wazuh rule on score | Needs the declared objective and action history |

## Layer 1 — Rule-of-Two accounting

Meta's Agents Rule of Two (31 October 2025) states that until prompt injection can
be reliably detected and refused, an agent should satisfy **no more than two of
three properties within a session**: processing untrusted input, accessing
sensitive data, and changing state or communicating externally. An agent needing
all three without a fresh context window should not operate autonomously and
requires at minimum human-in-the-loop supervision.

Everything needed is in the hook stream. Lives in `ambitd` because the bits are
live session state and the gate must return inline.

Three bits per session, monotonically set (never cleared within a session; see the
honest limitation below).

**Implemented, in shadow mode.** `internal/r2` classifies each event against the
bullets below in isolation; `internal/collector`'s `sessionState` accumulates the
bits monotonically, keyed on session_id, the simplest scoping there is. The gate table
further down runs in shadow too (`internal/gate`): its verdict is recorded on every
`PreToolUse` with `policy_shadow=true` and never returned, so nothing about a session's
behavior changes. The point is to let a real cohort's
usage answer how fast a long session saturates to all three bits with data
instead of argument.

Two things this surfaced, worth stating rather than only in code comments:

- **Subagent inheritance is free, not implemented.** Claude Code gives a subagent
  the same top-level session_id as its parent, distinguished only by
  `agent_id`/`agent_type` (code.claude.com/docs/en/hooks). Keying `sessionState` on
  session_id alone means a subagent's tool calls read and write the exact same bits
  as its parent: inheriting is the conservative default, achieved by the
  session-id keying rather than by a separate parent-bits-copy.
- **A new session_id is a genuine reset, for all three bits, not just A.** `/clear`
  is reported to regenerate the session_id without re-firing `SessionStart`
  (`anthropics/claude-code` issue #70606 — a community report, not primary
  documentation), so the first post-`/clear` event lands on an empty
  `sessionState`. That is unsound for B and C specifically — the credential already
  read or the tool already reachable does not actually reset — and this
  implementation does not solve it. It is the behavior shadow mode needs
  to measure the cost of.

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
- An MCP tool returning data from a system labelled sensitive: the `sensitive` tool label
  (`mcp_tool_labels`, per tool; see the README)

**Bit C — state change or external communication.** Set by:
- Bash command with network capability (`curl`, `wget`, `nc`, `ssh`, `scp`,
  `git push`, package publish)
- `Write` / `Edit` outside the working directory
- An MCP tool that is not `readOnlyHint: true` — and per
  [02](02-architecture.md)'s asymmetry, a server *claiming* read-only earns no
  relaxation, so in practice treat every MCP tool on a non-internal server as
  C-setting unless an operator has explicitly classified it
- Git push, PR creation, package publish, any outbound API write

**The gate**, in `ambitd`, on `PreToolUse`:

| Action class | Third-bit policy |
| --- | --- |
| Credential-path read after A | `deny` |
| Outbound network from Bash after A and B | `deny` |
| `git push` / publish after A and B | `ask` |
| Write outside working dir after A and B | `ask` |
| MCP non-read-only tool after A and B | `ask` |
| Everything else | `allow` + alert |

Start all of these at `ask` or `allow`+alert and promote to `deny` only with
baseline data (observe before enforce; see the Roadmap in the README).

**Implementation status: shadow verdicts (`internal/gate`).** The table is evaluated on every
`PreToolUse` and recorded as `policy.{decision,reason,rule_ids,bundle_version}` with
`shadow: true`. The hook still answers `{}`. Wazuh rules 100320–100323 surface the verdicts,
with runbook R2. Three choices the table leaves open are fixed in code and stated here:

- **"After A" means before this action.** A `curl` sets A through its own output, but the row is
  about acting after untrusted input arrived.
- **The listed rows fire whenever their precondition holds; "everything else" fires only on the
  action that completes the trifecta.** Otherwise a long session would alert on every call.
- **Push and publish outrank the general network row**, so a `git push` after A and B asks
  rather than denies, as the table says.

The verdict is computed under two scopings side by side: per session, which is the one the
policy fields carry, and per prompt turn (candidate 3 below), which stays in the spool as
`policy.alternatives` and in the replay report. That is the comparison the scoping choice
needs. First results:

- **The hand-written corpus** exercises every row. It shows the cost case the README warns
  about: a developer who reads a provider's docs and then their own `.env` is denied by
  `r2.credential_after_a`. It also shows the scoping difference: a `git push` two turns
  after a credential read is an `ask` under session scoping and nothing under turn scoping.
- **AgentDojo: the gate never fires.** Across 2,626 published runs (Claude 3.7 Sonnet, all
  suites; GPT-4o, banking), no verdict under either scoping: all 600 successful attacks are
  missed, and no benign run is interrupted. No run ever reaches bit B. AgentDojo's sensitive
  data arrives in tool results, and B has no source for that: "an MCP tool returning data from
  a system labelled sensitive" is one of the two bit bullets above that `internal/r2` does not
  implement. Without it, every
  A-and-B row is unreachable in an MCP-shaped environment, and the gate is reduced to its
  credential-path row. That makes a sensitivity label for MCP servers the input to build
  before any row is promoted.
- **A server-level label does not work, per-tool labels partly do.** A prototype that marked
  each AgentDojo suite's whole server sensitive made the gate ask on 354 of 485 benign actions
  (73%) and flag 104 of 132 benign Claude 3.7 runs. An unclassified server already sets A and C
  on every call, so the first call to a sensitive one completed all three bits, and every later
  call asked. A would-be block plus an edge then caught exactly what an edge alone caught: the
  gate added nothing. It was not merged. What was built is `mcp_tool_labels`: `untrusted`,
  `sensitive` and `read_only` per tool, with unlabelled tools keeping the conservative default.
  With AgentDojo's tools labelled (`testdata/agentdojo/mcp-tool-labels.json`, written by role
  and then checked against where the attack's injection marker actually appeared. The check
  moved two write tools, `delete_file` and `add_calendar_event_participants`, to `untrusted`,
  because they return the object they changed and its third-party content. After that, every
  tool the marker appeared in is labelled `untrusted`):

  | | edge | gate (deny or ask) | block and edge on one call |
  | --- | --- | --- | --- |
  | Claude 3.7, hostile runs caught | 37 / 47 (0.79) | 33 / 47 (0.70) | 23 / 47 (0.49) |
  | Claude 3.7, benign runs flagged | 26 / 132 (0.20) | 55 / 132 (0.42) | 19 / 132 (0.14) |
  | GPT-4o banking, hostile caught | 124 / 553 (0.22) | 532 / 553 (0.96) | 124 / 553 (0.22) |
  | GPT-4o banking, benign flagged | 4 / 25 (0.16) | 12 / 25 (0.48) | 3 / 25 (0.12) |

  The gate now discriminates, weakly. A benign task like reading email and replying is a
  genuine Rule-of-Two case, so it asks there too, and on Claude 3.7 the edge remains the
  better single signal. Labels also change what provenance sees, and one change is a loss
  worth stating: GPT-4o banking edges fall from 203 to 124, because 79 of the old catches were
  the user's own IBAN, read from `get_iban` or `get_user_info`, sent in the attacker's payment.
  Those tools are sensitive, not untrusted, so their results are no longer ingest. That
  lineage is data exfiltration rather than injection, and the sensitive-data edge (2d, below)
  recovers it.

**Honest limitation.** The rule is stated over a session, and "session" is doing
real work in that sentence. Compaction, `/clear`, subagents, and long-running
sessions all make the boundary ambiguous, and a monotonic bit over an 8-hour session
saturates to all-three and gates everything. Biggest open design problem in the
system.

Candidate scopings, to be chosen from shadow-mode data rather than argument:

1. **Monotonic per session** — the current implementation. Provably conservative;
   almost certainly unusable on long sessions.
2. **Decay** — bits expire after N turns or M minutes without reinforcement. Tunable,
   but the constant has no principled basis and an attacker who knows the window waits
   it out.
3. **Per-prompt-turn windows** keyed on `prompt_id`. Matches the natural unit of work
   and the observation that most injection-to-action sequences are short; loses slow
   attacks that span turns.
4. **Per-ingest scoping** — bind each provenance ingest to a decaying relevance and
   evaluate C-actions against *live* ingests. Most faithful to what the rule
   expresses; most complex.

Clearing bit A on compaction is unsound (a summary can carry the injected
instruction), and not clearing it is what makes long sessions saturate.

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

**Implementation status (`internal/prov`, alert-only).** 2a and 2b are built; 2c is not.
The engine keeps a per-session set of keyed fingerprints from untrusted ingest, intersects
it with every `PreToolUse` input, and puts the result on the event as `provenance.edges`.
It changes no hook response and sets no decision. Rule 100283 reads the strongest edge.
What it does and does not do, because the design above overstates nothing and the code
should not either:

- **"Untrusted ingest" is Rule-of-Two bit A.** A `PostToolUse` result registers exactly
  when the same call set bit A (`internal/r2`), so the two layers cannot disagree. Content
  from an operator-trusted domain or server does not register.
- **A value the ingest did not introduce does not register.** What the user typed in a
  prompt, and what the agent passed in the same call's input, are excluded. Without this,
  every follow-up request to a host the agent was sent to would be an edge, because a page
  names its own host. The cost is stated in `prov.Ingest`: a page that points the agent
  back at the host it came from draws no *domain* edge, though a spelled-out URL still draws
  a *URL* edge. A value the user typed *after* it was ingested is not retroactively
  excluded.
- **Confidence is by class:** URL and IBAN 0.95; email and high-entropy token 0.90; IP and
  domain 0.80; shingle 0.30 (advisory, and off unless `EnableShingles`). A domain the operator
  lists in `trusted_content_domains` is **down-weighted to 0.40, not dropped** — a trusted
  code host is also an exfiltration sink, and s1ngularity wrote to public repositories on
  one.
- **The set is bounded and says so.** 256 fingerprints per result, 8192 per session, oldest
  evicted first. Truncation and eviction are counted (`prov_truncated`, `prov_evicted` in
  the `ambitd stopped` log line); a non-zero count means an absent edge in some session is
  weaker evidence than it looks. Neither bound is sound: a flood can still push older
  fingerprints out, and the per-ingest cap is only what makes that expensive.
- **Not covered:** instruction files. `InstructionsLoaded` carries a path and no content,
  so a poisoned `CLAUDE.md` taints the session (`instructions:untrusted`) but contributes no
  fingerprints. Paraphrase and reconstruction defeat the intersection entirely, as above.
  Cross-session matching is D10's separate, scalar form.
- **Taint labels are in the spool but cross only on events that cross anyway.** A new label
  does not by itself make an event cross; that would add volume before the interesting
  fraction has been measured.

### 2a — Session taint (sound, coarse)

Bit A as a label. Reliable, useless alone for attributing a *specific* action. Emitted as
`web:hmac:<domain>`, `mcp:<server>`, `bash:network`, `file:untrusted` or
`instructions:untrusted`, on the event that first introduces each label in a session.

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

**The intersection runs in `ambitd`, in memory, and only the resulting edge is
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

### 2d — Sensitive-data edges (unsound, specific; spool only)

The same fingerprinting, pointed the other way. Edges answer "did untrusted content steer
this action". A sensitive-data edge answers "is private data leaving in it": a result that set
bit B (a credential read, a tool labelled `sensitive`) registers its fingerprints in a second
set, and an action that can act or reach outside (bit C) is matched against it. The novelty
rule carries over, so a value the user typed is theirs to send and never matches. The edge is
recorded as `provenance.exfil` on the rich event only. It has no flattened field and no rule
until its precision is established.

**Payload only, not addressing.** The match reads an acting call's payload and skips its
addressing fields (`recipient`, `to`, `participants`, `url`, `channel`, `file_path` and the
like, by name). That choice was measured. Matching the whole input on AgentDojo (labelled
tools) mostly found the user addressing someone known: a participant read from a calendar
event and then emailed, a payee read from scheduled transactions and then paid. That pattern
was as common in benign runs as in hostile ones. Restricted to the payload:

| | edge on the attacker's own call | incidental only | benign runs flagged |
| --- | --- | --- | --- |
| GPT-4o banking, whole input | 136 / 553 | 67 | 4 / 25 |
| GPT-4o banking, payload only | 136 / 553 | 0 | 1 / 25 |
| Claude 3.7, whole input | 11 / 47 | 6 | 21 / 132 |
| Claude 3.7, payload only | 2 / 47 | 7 | 14 / 132 |
| Claude 3.7, payload only, hostnames left out | 0 / 47 | 3 | 8 / 132 |

On GPT-4o banking the payload rule keeps every catch on the attacker's payment (the user's
own IBAN sent in its subject) and drops every incidental one. On Claude 3.7 the nine catches it
loses were all the attacker's own address in a recipient field, which arrived through a tool
labelled both untrusted and sensitive. Every one of those runs is still caught by a provenance
edge, so nothing is lost overall; the whole-input match was counting provenance twice. What the
class misses is a short value leaving in a body (a six-digit security code), which no
fingerprint class covers. Matching by field name is a convention, not a schema, and a tool that
puts its payload in a field called `recipient` hides it.

**Hostnames are left out of the set.** After payload-only matching, the benign flags that remained
on Claude 3.7 were mostly one class. Of the 14 benign runs flagged, 12 had a `domain` match, and
the typical case is a channel summary that names the sites people had shared: a hostname in a
sensitive tool's result is public information, not private data. The sensitive-data set no longer
registers or matches domains (the untrusted-content set still does, since a host a page names is
what a redirected action looks like). Measured on the same runs, with the hostile and the two
benign labels kept apart this time:

| | hostile runs with an edge | no-attack runs flagged | user-requested-goal runs flagged |
| --- | --- | --- | --- |
| Claude 3.7, before | 9 / 47 | 7 / 97 | 7 / 35 |
| Claude 3.7, after | 3 / 47 | 3 / 97 | 5 / 35 |
| GPT-4o banking, before and after | 136 / 553 | 0 / 16 | 1 / 9 |

The cost is real and worth stating. The two Claude 3.7 runs where the attacker posted the channel
messages to its own site were caught only by a hostname that happened to sit in the messages, not
by the secret itself (a short key no class covers), so they are no longer caught here. Provenance
catches both runs. GPT-4o, where the useful matches are IBANs and high-entropy tokens, is
unchanged. So on Claude 3.7 this class now has no catch on the attacker's own call that
provenance does not already have, and what remains is a weaker signal than the one it replaced.

**Read the remaining flags with the labels in mind.** A `user-requested-goal` run is AgentDojo's
attack task given to the agent as the user's own request, and the adapter labels it benign. Five of
the eight remaining benign flags are those: the agent sends account numbers, personal details, files
or an email's contents on, because it was asked to. That is the attack's shape with the user's consent,
and no matching rule can tell the two apart; the novelty rule only covers values the user typed.
Counting them as false positives overstates the problem, and counting them as detections would
overstate the recall, so both labels are reported.

**Verbatim-copy matching was tried and rejected.** Shingles (five-word runs) would catch a posted
dump of messages directly. Enabling them for the sensitive set on Claude 3.7 raised hostile runs
with an edge from 9 to 12 and benign runs flagged from 14 to 23, because a summary reuses
phrases from what it summarizes. On GPT-4o it moved 136 to 142. Not worth the noise, and shingles
stay off.

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
- Scoring runs **asynchronously in `ambitd`**. It never gates a `PreToolUse`: too
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

**Implementation note for the cost pre-filter:** if scoring is gated to
actions that already carry an R2 signal, gate it on that event's own
`r2.ClassifyTool(...).Any()`, never on `sessionState`'s `Transition` field.
`Transition` is correct for `internal/filter`'s alerting use (new-to-this-session, so
Wazuh isn't re-alerted on every repeat) and wrong here — it would silently skip every
repeat action once a bit is already set for the session, which is exactly the
sixteenth flight booking or tenth bank transfer a session-shape attack hides among.

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
<group name="ambit,ambit_credential,">
  <!-- Base: ambitd reported a credential-zone read. -->
  <rule id="100210" level="5">
    <decoded_as>json</decoded_as>
    <field name="kind">^tool_pre$</field>
    <field name="path_zone">^credential$</field>
    <field name="path_op">^read$</field>
    <description>ambit: credential-zone read by $(agent_kind) session $(session_id)</description>
    <mitre>
      <id>T1552.001</id>
    </mitre>
    <group>ambit_d2,runbook_D2,</group>
  </rule>

  <!-- D2: many of them, same session, short window. -->
  <rule id="100211" level="12" frequency="8" timeframe="120" ignore="300">
    <if_matched_sid>100210</if_matched_sid>
    <same_field>session_id</same_field>
    <description>ambit D2: credential sweep - 8+ credential-zone reads in one session within 120s</description>
    <mitre>
      <id>T1552.001</id>
      <id>T1555</id>
    </mitre>
    <group>ambit_d2,runbook_D2,</group>
  </rule>
</group>
```

`same_field` on `session_id` is what makes this a *sweep by one agent* rather than
eight unrelated reads across the fleet. Thresholds are placeholders to be set from
M2 baseline data, not from intuition — a repo with forty `.env` files in a monorepo
will trip 8-in-120s during an ordinary build.

### D4 and D5 — shipped

These two are no longer shapes. The rules are in
`deploy/wazuh/rules/ambit_mcp_rules.xml` (IDs 100230–100248) with runbooks in
`deploy/wazuh/runbooks/`, and they read the `mcp_list` events `mcp-interpose` produces:
`mcp_baseline_state` for D4's verdict, `mcp_changed_fields` for what moved,
`mcp_scan_classes` for D5's finding classes.

Three decisions there are worth repeating here, because each was forced by the rule
engine rather than chosen:

1. **The listing roll-up and the per-tool verdict use different field names.** A Wazuh
   rule tests presence and equality and cannot easily test absence, so if the per-server
   summary and the per-tool events both carried `baseline_state`, every drift would
   raise two alerts and no rule could tell the roll-up from the finding. The summary
   carries `mcp_tool_count`; only per-tool events carry `mcp_baseline_state`. The
   roll-up stays in the spool as `mcp.worst`.
2. **Per-tool events cross only when they say something.** [04](04-data-model.md)
   budgets `mcp_list` at one event per server per session, and a 60-tool server matching
   its approved baseline would otherwise spend 60 events per session saying so. The
   filter drops the quiet ones; the spool keeps them.
3. **Array-valued fields are matched with unanchored literals.** How a `<field>` regex
   matches a multi-valued field is unverified, and an unanchored
   literal is the form that works under either behavior. A test fails the build if
   anyone anchors one.

The false-positive posture is stated in the D5 runbook rather than implied: two of its
five classes — `sensitive_file_ref` and `sensitive_action` — are expected to fire on
servers whose job involves secrets or HTTP, which is why they sit at level 7 with the
false positive named, and why every finding carries a pattern id so a noisy pattern can
be retired on evidence during M1.

### D11 — fail-open run, same shape

```xml
<group name="ambit,ambit_integrity,">
  <rule id="100260" level="5">
    <decoded_as>json</decoded_as>
    <field name="policy_decision">^fail_open$</field>
    <description>ambit: ambitd unavailable, tool call failed open on $(endpoint_id)</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>ambit_d11,runbook_D11,</group>
  </rule>

  <rule id="100261" level="12" frequency="5" timeframe="300" ignore="600">
    <if_matched_sid>100260</if_matched_sid>
    <same_field>endpoint_id</same_field>
    <description>ambit D11: sustained fail-open - ambitd repeatedly unavailable on one endpoint</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>ambit_d11,runbook_D11,</group>
  </rule>
</group>
```

### D7's finer half — absence of the ambitd stream

Rule 504 covers the endpoint going dark. The harder case is the Wazuh agent alive
while `ambitd` is dead: the endpoint heartbeats, FIM and SCA keep reporting, and only
the `ambitd` event stream stops.

Wazuh rules fire on events, not on their absence, so this is not expressible as a
correlation rule. Two options, and the second is better:

1. `ambitd` emits a periodic `ambitd_health` heartbeat event; a scheduled query on
   the indexer flags endpoints with no heartbeat in N minutes. Requires something
   outside the rule engine to run the query.
2. **The Wazuh agent reports on `ambitd`'s liveness rather than `ambitd` reporting on
   its own.** SCA check 10007 (`p:ambitd`) already runs on the Wazuh agent's
   schedule and fails when the process is gone. A failed SCA check is an event, so
   this needs no external scheduler and — critically — the signal comes from a
   *different process than the one being watched*, which is the whole point when the
   adversary can kill processes.

Recommendation: option 2 as primary, with option 1's heartbeat retained because
`p:ambitd` cannot tell a wedged daemon from a healthy one. Combined, a wedged
`ambitd` shows as "process present, heartbeat stale."

**A third signal, now implemented: stream discrepancy.** `ambitd` receives Claude
Code's OTel export on a loopback OTLP/HTTP receiver and counts tool calls on both
the hook path and the OTel path. Exactly one path silent while the other reports
means a collection path has stopped, and `ambitd` sets its health status to
`degraded`, which crosses to Wazuh as an `ambitd_health` event. This catches cases
neither of the above does: the hook removed from settings while the daemon runs
(OTel active, hook silent), and the OTel destination redirected or the encoding
switched to protobuf (hook active, OTel silent).

Both paths quiet is an idle endpoint, not a discrepancy. And the comparison is
"one silent", not a ratio — the streams legitimately differ in what they see, so
a count mismatch is normal and only total silence on one side is a signal.

### D12 — managed-settings drift (new)

SCA policy from [02](02-architecture.md). A failed check raises an SCA alert
natively; the custom rule raises severity and attaches the runbook:

```xml
<group name="ambit,ambit_integrity,">
  <rule id="100270" level="12">
    <if_sid>19007</if_sid>
    <field name="sca.policy_id">^ambit_managed_settings$</field>
    <description>ambit D12: managed-settings assertion failed - $(sca.check.title) on $(agent.name)</description>
    <mitre>
      <id>T1562.001</id>
    </mitre>
    <group>ambit_d12,runbook_D12,</group>
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
  <description>ambit D10: fingerprint $(prov_fp_notable) seen in two sessions - possible cross-agent propagation</description>
  <mitre>
    <id>T1105</id>
  </mitre>
  <group>ambit_d10,runbook_D10,</group>
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

- `ambitd` pre-selects, per event, at most one **notable fingerprint** — from the
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

### What writing the rules exposed

All twelve detectors now have rules under `deploy/wazuh/rules/` and a runbook each under
`deploy/wazuh/runbooks/`. Writing them surfaced four gaps between what this document
specifies and what the pipeline emits. Each is marked in the rules themselves so nobody
reads an inert rule as a quiet fleet.

1. **`agent_entrypoint` has no emitter.** D1 is specified in terms of a non-interactive
   entrypoint, [04](04-data-model.md) gives the field, and nothing populates it: the hook
   payload ambitd parses carries no entrypoint field and the OTel path has no equivalent
   attribute. Rule 100204 is marked `ambit_pending_emitter` and cannot fire. What D1 does
   detect today is `bypassPermissions` combined with a sensitive action, which is a weaker
   claim than "no human present" and the runbook says so.
2. **MCP annotations never reach tool *call* events.** The interposer reads them from
   `tools/list` and they cross on `mcp_list` events, but a call event comes from the hook
   path, and a hook payload has no annotations. So `tool_mcp_destructive_hint` and
   `tool_mcp_openworld_hint` are absent on every `tool_pre` and `tool_post`. This makes
   rule 100303 inert, and it makes the destructive-hint criterion in `internal/filter`
   inert too — harmlessly, because an unclassified server makes those events cross anyway.
   The fix is ambitd caching the interposer's per-tool annotations and enriching call
   events, which is M2 work.
3. **Sandbox allowlist denials have no field at all.** D9 lists them as a signal; the
   schema has nowhere to put one, so a *blocked* exfiltration attempt is invisible to the
   detector. This is a schema addition, not an unpopulated field, and it is the one gap
   here with nothing to mark.
4. **An untrusted zone now overrides a trusted-repo prefix**, which was a bug rather than a
   gap. A `CLAUDE.md` inside `node_modules` of a trusted repository was being reported as
   trusted, because the prefix check matched the dependency's parent path — which would
   have made D8 miss dependency-carried instructions, its main case. Fixed in the
   collector, with a test.

Two further limits are inherent rather than fixable: **absence is not expressible** in a
rule engine, which is why D1's "SessionStart with no UserPromptSubmit" and D7's "no
heartbeat for N minutes" are not rules; and **volume or destination profiling is not a
rule**, which is why D9 reports egress shape rather than anomaly.

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
| D7 | **Telemetry gap.** Rule 504 for endpoint silence; SCA `p:ambitd` plus stale heartbeat for daemon death. | Daemon suppression |
| D8 | **Poisoned instruction file.** `InstructionsLoaded` under a newly cloned or untrusted path. | Repo-carried injection |
| D9 | **Egress anomaly.** Outbound volume or destination outside the endpoint's profile; any sandbox allowlist denial. | Exfiltration |
| D10 | **Cross-agent fingerprint match.** Scalar tripwire as a rule; full set intersection as a scheduled job. | Prompt Infection / propagation |
| D11 | **Fail-open run.** Repeated `ambitd` unavailability. | Suppression |
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

**Implementation status.** The replay half is built: `cmd/ambit-replay` (`internal/replay`)
feeds trajectories to the real collector in-process and reports precision, recall, a
confidence-floor sweep and Rule-of-Two saturation depth; the README documents the format.
It measures the provenance engine and R2 accounting. It does not yet measure the Wazuh rules
(those have their own fixture path below) or goal drift (M4). `testdata/replay` holds 18 scenarios written alongside the engine, by the same author,
which is exactly the bias NIST's finding below warns about, so its numbers pin behavior and
must not be read as a detection rate. The AgentDojo adapter is the first corpus that avoids
that bias. Its attacks are AgentDojo's, not adapted to ambit, and that cuts both ways: by the
warning below, a generic baseline overstates a detector's coverage, so the AgentDojo recall is
an upper bound against an attacker who knows to paraphrase. SHADE-Arena and ControlArena have
no adapter yet.

What the first runs found, recorded because they are the reason a harness is worth having:

- **A real recall bug**, now fixed. A credential glued to its key (`SERVICE_KEY=<token>`,
  `--token=<token>`) tokenized as one run, so it never matched the bare token an ingested page
  carried. The extractor now also fingerprints each `=`-separated segment.
- **A by-design miss, now recorded.** The redactor strips the value of any `…token=<value>`
  before feature extraction, so a planted secret used that way draws no edge and sets bit B
  instead. Redaction takes precedence over provenance.
- **First measurement against real runs: AgentDojo.** `agentdojo-convert` maps AgentDojo's
  published run logs onto hook payloads (each suite an unclassified MCP server), and
  `scripts/agentdojo-measure.sh` reproduces the numbers below from upstream commit `089ed468`.
  Run-level truth comes from AgentDojo's own checker: a run whose injected attack succeeded is
  hostile, a run with no injection is benign, and failed, errored and DoS attack runs carry
  no label. A run is positive if any action in it drew an edge, so the benign-run rate is the
  number to read recall against.

  | Claude 3.7 Sonnet, `important_instructions` | hostile runs | caught | benign runs | edge drawn |
  | --- | ---: | ---: | ---: | ---: |
  | banking | 6 | 0 | 25 | 4 |
  | slack | 25 | 25 | 26 | 12 |
  | travel | 1 | 0 | 27 | 1 |
  | workspace | 15 | 12 | 54 | 12 |
  | **all** | **47** | **37 (0.79)** | **132** | **29 (0.22)** |

  These are the default configuration, no tool labels, with the `iban` class. On GPT-4o
  (2024-05-13), banking suite, all attacks: 203 of 553 successful attacks caught (0.37), and 5
  of 25 benign runs drew an edge (70 and 3 before the IBAN class existed; see the first miss
  below). At the action level, 51 of 485 actions in benign Claude 3.7 runs drew an edge (0.11).
  Re-measured from a fresh clone of `main` at upstream `089ed468`, after the sensitive-data
  edges merged: the figures above and the labelled and gate figures elsewhere in this
  document reproduced exactly.

  Every case was read, not just counted. What they show:
  - **The edges in successful attacks land on the attacker's own action**, for example
    `invite_user_to_slack` with the attacker's address, or a fetch of the attacker's site. They
    are not incidental.
  - **The false positives are legitimate carry-through**, the case 2b predicts. The user's own
    task requires a value from a tool result: an IBAN from the transaction history, an address
    from a web page, URLs posted in a channel. The edge cannot tell that lineage from an
    injected one, and confidence does not help, because most are email and domain matches at
    0.80–0.90.
  - **The misses have four causes, and only one is a fixable gap.** (1) *Account numbers.*
    AgentDojo's attacker IBAN `US133000000121212121212` has entropy 2.23, below the 3.2
    high-entropy floor, so it is never fingerprinted. A real-format German IBAN (`DE89…`, 2.94)
    misses too, so whether an IBAN is caught depends on its digits. That was 403 of the 483
    GPT-4o banking misses. **An `iban` class now exists** (strict: registry country, that
    country's length, mod-97 check digits; printed and compact forms are one fingerprint).
    It does **not** catch AgentDojo's attacker account, which is not an IBAN: the US issues
    none and its check digits fail. A real attacker moving money needs a real IBAN, and a looser
    "IBAN-shaped" rule would fingerprint every order number, so the strict rule is deliberate.
    Re-measured, it still helps, and every changed run was read:
    GPT-4o banking goes from 70 to 203 hostile runs with an edge. Of the 133 new ones, **82
    have the edge on the attacker's own payment**: AgentDojo's injection tasks make the agent
    put the user's data in that payment, such as their IBAN or a contact's, and the class catches
    the stolen account number on its way out. **51 are incidental**: the only edge is on a
    legitimate payment the user asked for, so run recall overstates the gain by that much.
    The cost is legitimate carry-through again. One more benign run is flagged on each model
    (Claude 3.7: 27 to 29 of 132; GPT-4o: 3 to 5 of 25), where a user pays an account read from
    a bill. A redirected-payment attack has exactly that shape too, which is why the edge must
    never page alone. (2) *Short or common values*, such as a new password of
    `new_password` or `delete_file(13)`, have no class at all, and should not. (3) *Attacks on the
    agent's answer.* The travel injections that only change what the agent says produce no
    action, so an action monitor cannot see them. (4) Paraphrase, as above, which the hand-written
    corpus already records.
- **Confidence does not separate the false positives in the starter corpus.** The benign
  carry-through cases (following a documentation link, putting an article's URL in a summary)
  are full-URL matches at 0.95, so raising the floor removes recall and keeps them. The edge
  cannot be the page condition alone; this is the empirical case for the composite below.

Use the public corpora as the regression suite: replay trajectories through `ambitd`, measure
detection and false-positive rate per detector. Wazuh rules get their own test path —
`wazuh-logtest` takes a log line and reports which decoder and rule matched, so rule
correctness is testable from a fixture file of `events.jsonl` lines without a live
fleet.

NIST's finding carries a methodological warning worth adopting: **evaluate against
attacks adapted to our detectors, not only generic baselines.** A detector tuned on
baseline attacks overstates its own coverage.
