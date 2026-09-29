# 07 — Open questions

Decisions this design does not make, ordered by how much they change the build.
Each states the options, the tradeoff, and a recommendation where there is one.

## Q1 — What is a "session" for Rule-of-Two accounting? *(blocking M2)*

The biggest unresolved problem in the design. Meta's rule is stated over a session
with the remedy being "a fresh context window." Claude Code sessions do not map
cleanly onto that:

- **Compaction** (`PreCompact` / `PostCompact`) replaces context with a summary. Is
  the injected instruction still present? Sometimes — a summary can carry it. So
  clearing bit A on compaction is unsound, but *not* clearing it means any long
  session saturates to all-three and the gate fires on everything.
- **`/clear`** genuinely resets context and arguably resets A. But the *endpoint*
  state that bits B and C are about — the secret already read, the tool already
  reachable — does not reset.
- **Subagents** run in the same process and share sandbox config, but have their
  own context. `SubagentStart`/`SubagentStop` allow subtree scoping. Should a
  subagent inherit the parent's bits? Inheriting is conservative and may make
  subagents useless; not inheriting creates a laundering path where the parent
  fetches untrusted content and a subagent performs the action.
- **An 8-hour session** will set all three bits within the first hour of any real
  work.

Options:
1. **Monotonic per session.** Simplest, provably conservative, almost certainly
   unusable on long sessions.
2. **Decay.** Bits expire after N turns or M minutes without reinforcement.
   Tunable, but no principled basis for the constant, and an attacker who knows the
   window waits it out.
3. **Per-prompt-turn windows** using `prompt_id`. Matches the natural unit of work
   and the observation that most injection-to-action sequences are short. Loses
   slow attacks that span turns.
4. **Per-ingest scoping.** Instead of a session-wide bit A, bind each provenance
   ingest to a decaying relevance and evaluate C-actions against *live* ingests.
   More faithful to what the rule is trying to express; most complex.

**Recommendation:** ship M2 with option 1 in shadow mode specifically to measure how
fast saturation happens, then choose between 3 and 4 with that data. Do not pick on
argument — this is exactly what shadow mode is for. Treat subagent inheritance as a
separate call and default to inheriting (conservative) with the laundering path
documented.

## Q2 — Build `mcp-interpose` or adopt an existing gateway? **RESOLVED.**

Several open-source MCP gateways already do interception, per-tool allowlists,
argument/result guardrails, and audit trails ([06](06-prior-art.md)). Our unique
need is narrow: metadata hashing, baseline diffing, and emission in our event
schema.

Options: write a minimal purpose-built interposer; fork a gateway; write a plugin
for one.

**Decision: build a minimal purpose-built interposer in Go. Adopt neither
candidate, and write a plugin for neither.** The evaluation, with evidence and
the commits it was run against, is [08](08-mcp-interpose-decision.md).

Two findings settled it. **Neither gateway does the thing that is our
contribution:** neither repository hashes tool metadata or keeps an approved
baseline, so D4 is ours to implement under either option. And **both aggregate
servers behind one client entry, which renames tools** — lasso to
`<server>_<tool>`, enkrypt to a single `enkrypt_secure_call_tools` — breaking the
`mcp__<server>__<tool>` identity that `internal/hook/payload.go:157` already
parses and that managed-settings permission rules match. Adopting either makes
Claude Code's own permission model coarser in order to install our telemetry,
which is the wrong side of the line this project draws.

Runners-up on the specifics: lasso drops MCP annotations when it re-registers
tools and enforces at M1 by rewriting `.mcp.json` — the file our own D6 FIM watch
is pointed at — including on internal errors; enkrypt genuinely has the right
hook (`validate_tool_registration`, carrying description, schema and
annotations), but reaching it means a 75k-LOC web stack on every developer
endpoint and a default guardrail path that POSTs tool content to
`api.enkryptai.com`, one config key away from contradicting Q3.

Taken from them anyway, both additive and neither a dependency on the endpoint:
lasso's three-category description-pattern corpus as a first draft for D5, and
enkrypt's `bad_mcps/` servers as M1's mutation fixtures.

**The failure mode Q2 warned about still applies to what we build.** [08](08-mcp-interpose-decision.md)
carries the scope fence — not an auth layer, not multi-tenant, not an aggregator,
not a content guardrail — and the conditions that would reopen this, chiefly a
cohort that turns out to depend on HTTP/SSE MCP servers a stdio wrapper cannot
wrap.

## Q3 — How much content leaves the endpoint? *(blocking M0)*

[04](04-data-model.md) defaults to digests and keyed features, with content only
under narrow policy. This is the right security posture and it will make incident
investigation harder — an investigator looking at a provenance edge sees "a domain
matched" and not *which* domain, unless the blob was retained or they can reach the
endpoint's local reverse map.

Options: digests only; digests plus narrow retention triggers (the current
proposal); full content behind access control and audit.

**Recommendation:** start with the current proposal and revisit after the first real
investigation, which will show concretely what was missing. Needs sign-off from
whoever owns data handling, alongside the retention numbers in
[04](04-data-model.md), which are engineering guesses and not a compliance position.

**Partly resolved by the MSSP decision.** The *external* half of this question is now
settled: zone labels in cleartext, paths as keyed digests, HMAC key held by us, digest
resolution on request from our side ([01](01-threat-model.md)). What remains open is
the *internal* half — how much content we ourselves retain in the spool and blobs, and
for how long — plus the contractual question of what the MSSP agreement actually
commits us to. The retention split in [04](04-data-model.md) is the current proposal;
the contract has to match it, and the digest-resolution turnaround needs a real SLA
rather than a good intention.

## Q4 — Who reviews the queue? *(blocking M2 exit)*

Layers 2 and 3 produce alerts that need human judgment, and M2's exit criteria
require reviewing every would-have-blocked event. That is a standing operational
cost, and the system's usefulness is capped by it: a queue nobody reads is a
detector nobody has.

Unresolved: who owns it, what the expected daily volume is, what the escalation path
is, and what happens to the promotion ladder if review capacity does not exist. If the
answer is "nobody," M3 should be reconsidered — enforcement without review is a gate
whose false positives nobody learns about.

**Partly answered by the MSSP decision, but not eliminated.** Wazuh supplies the queue
itself — dashboard, RBAC, severity — and an external firm supplies analysts, which is
most of the capacity problem. What it does not supply is the two things only we can do:
**writing runbooks an outsider can execute** ([03](03-detection.md)) and **serving
digest-resolution and spool-pull requests** ([01](01-threat-model.md)). Both are
standing internal commitments, and an MSSP engagement makes them load-bearing rather
than optional — an unresolvable alert is worse than no alert, because someone paid
attention to it and got nothing. Still needs an owner on our side.

## Q5 — Does `ambitd` handle non-Claude-Code agents?

The user's targets are Claude Code and MCP. Other CLI agents (Gemini CLI, Amazon Q,
Codex) were also weaponized in s1ngularity, and MCP servers are shared across
clients, so `mcp-interpose` covers them for free at the tool layer but nothing
covers their hook-equivalent surfaces.

Options: Claude Code only; normalized schema plus thin adapters later (the schema in
[04](04-data-model.md) already has `agent.kind` for this); multi-agent from the
start.

**Recommendation:** Claude Code only through M3, with the schema left agent-agnostic
so adapters are additive. Do not build adapters speculatively.

## Q6 — Is the goal-drift scorer worth its cost?

Layer 3 runs a model on a large fraction of tool calls. At fleet scale — the
[04](04-data-model.md) estimate is ~126k tool calls/day for 63 agents — that is a
real per-token bill and a real latency budget even async.

Unresolved: sample rate versus full coverage; which model; whether a cheap
deterministic pre-filter (only score actions that set an R2 bit or carry a
provenance edge) captures most of the value at a fraction of the cost.

**Recommendation:** pre-filter. Score only actions that already tripped a
deterministic or provenance signal. This loses the pure-decomposition case where no
individual action trips anything, which is exactly the A4 threat, so measure that
loss on SHADE-Arena before accepting it.

## Q7 — Fail-closed set membership.

[02](02-architecture.md) proposes failing closed for credential writes, Bash egress,
`git push`, destructive MCP tools, and out-of-workdir writes, and open for the rest.
Every member of that set is a potential fleet-wide work stoppage if `ambitd` has a
bug.

Unresolved: whether the set should start empty and grow, and whether "fail closed"
should mean `deny` or `ask` — `ask` degrades to a human decision rather than a hard
stop, which may be the better failure mode for all of them.

**Recommendation:** fail-closed means `ask`, not `deny`, for the whole set. A
developer answering a prompt during an `ambitd` outage is a far better failure mode
than a blocked task with an opaque reason.

## Q8 — Policy bundle signing and key management.

`ambitd` must refuse unsigned or downgraded bundles ([02](02-architecture.md)), which
means a signing key, a rotation story, and a trust root on every endpoint. Reuse the
existing MDM trust root if there is one, or run a separate signing chain.

Not blocking until M3, but it needs an owner before M3 starts, because retrofitting
signing onto a deployed unsigned-bundle system is worse than doing it once.

**One constraint is now fixed rather than open:** bundles do **not** travel over
Wazuh's centralized-configuration channel, even though it exists and would be
convenient ([02](02-architecture.md)). Doing so would give anyone with manager access —
including an MSSP under option (b) of Q11 — the ability to rewrite the inline gate.
Separate path, separate trust root. What remains open is the key management itself:
reuse the MDM trust root, or run an independent signing chain.

## Q9 — Naming. **RESOLVED.**

The project is **ambit**: the scope of authority an action falls inside or outside
of, which is the question the Rule-of-Two gate, the provenance layer and goal-drift
scoring are each asking in their own way.

Rejected on collisions, all checked: `remit` (Adrian, a runtime AI-agent security
tool with a Claude Code plugin, uses "out-of-remit" in its own description),
`mandate` (`agent-mandate` occupies nearly this problem space), `lodestar`
(ChainSafe's Ethereum client), `purview` (Microsoft Purview, an adjacent governance
product), `adrift` (a web proxy network). `spoor` was dropped for being one letter
from "spool", which this codebase already uses.

Components: **`ambitd`** (endpoint daemon), `mcp-interpose`, and Wazuh as the fleet
plane. Rule groups are `ambit_*`, the SCA policy is `ambit_managed_settings`, sinks
live under `/var/lib/ambit/`.

**One consequence was a bug fix rather than cosmetics.** The daemon was `agentd`,
and Wazuh ships its own `wazuh-agentd` on every monitored endpoint. The SCA
documentation does not say whether `p:` matches a process name exactly or by
substring; under substring matching, SCA check 10007's `p:agentd` would have matched
Wazuh's own daemon and passed on every endpoint running the Wazuh agent, including
ones where ours was dead. That is a silent failure of D7's liveness half — the check
reports healthy precisely when it should fire. `ambitd` is distinct enough that the
matching rule no longer matters.

## Q10 — Claims resting on post-cutoff or secondary sources.

Flagged for verification by someone who can read the primary sources, because a
threat model built on unverified numbers is a liability:

- The GPT-6 "Astra" system card findings from the originating research brief
  (CoT-monitor evasion, covert sandbagging, the near-zero evasion rate against
  full-trajectory monitors). **Not verified.** The design does not depend on them —
  it depends on the action-monitoring-beats-reasoning-monitoring conclusion, which
  SHADE-Arena supports independently — but the brief's framing does.
- Claude Opus 4.6 Sabotage Risk Report (~18%/16% side-task success). Vendor-reported,
  not independently replicated.
- The July 2026 OpenAI–Hugging Face multi-agent incident. Unverified; cited in
  [01](01-threat-model.md)'s A5 only as motivation, and the Prompt Infection paper
  carries that argument on its own.
- mcp-scan's runtime proxy mode. Secondary sources only; primary repo docs did not
  confirm it. Affects Q2.
- CVE counts and the reported NSA/DoD MCP advisory (June 2026). Unverified; nothing
  in the design depends on them.

## Q11 — Wazuh multi-tenancy for third-party monitoring *(blocking MSSP onboarding)*

Left open deliberately. Wazuh's multi-tenancy is thin — it is not natively
multi-tenant the way commercial SIEMs are *(secondary sources; the architecture
patterns below are community practice rather than a documented product feature)*. Every
MSSP restriction in [01](01-threat-model.md) and [02](02-architecture.md) rests on
whichever model is chosen, so until this is settled those restrictions are intentions
rather than enforced controls.

Three options.

**(a) Manager per tenant.** A separate `wazuh-manager` per monitoring firm, optionally
sharing a dashboard and indexer.

- *For:* strongest isolation of rules, agent config, and active-response scope. Each
  firm's rule changes cannot affect another's. Naturally bounds AR dispatch to that
  manager's agents.
- *Against:* every endpoint runs one agent per manager, or agents are partitioned by
  which firm watches them — and partitioning defeats the point if two firms are meant
  to watch the same fleet. Reported limitation: when multiple managers feed one
  indexer, some internal Wazuh metadata is shared rather than tenant-scoped, so
  isolation is not clean at the indexer anyway. Operationally the heaviest.

**(b) Agent groups + API RBAC + index-level restrictions.** One manager. Tenants are
expressed as agent groups; each firm gets a role scoped to its groups, and indexer
restrictions limit which documents its users can read.

- *For:* one deployment to run. The supported path — agent group labels appear on every
  indexed alert, which is what index-level restriction keys on. Lets several firms watch
  the *same* agents with different scopes, which (a) cannot.
- *Against:* isolation is a configuration property, so a misconfigured role is a data
  leak, and the failure is silent. Rule definitions are global: a rule one firm wants
  is visible to all, and a noisy rule affects everyone's queue. Withholding AR dispatch
  is an RBAC permission rather than an architectural boundary — exactly the control
  [01](01-threat-model.md) leans on hardest, resting on the weakest mechanism here.

**(c) Forward alerts into each firm's own Wazuh.** We keep ours; alerts are relayed to
theirs.

- *For:* their analysts work in their own tooling with their own history and
  correlations across their whole client base. No access to our manager at all, so the
  AR concern disappears entirely.
- *Against:* **this changes the egress posture again, and it is the reason this option
  cannot be waved through.** [01](01-threat-model.md) assumes the MSSP reads a copy we
  host and control, under our RBAC and our retention. Forwarding means we are exporting
  alert data to infrastructure we do not operate, with their retention, their access
  control, and their breach exposure. Every digests-only guarantee becomes a term in
  their contract rather than a property of our deployment, and revocation stops being
  something we can do unilaterally. It also breaks the digest-resolution workflow, which
  assumes a request path back to us for alerts *we* still hold.

**Recommendation: (b), with (a) held in reserve, and (c) only if a firm's own platform
is a hard requirement of the engagement.** (b) is the supported path, is the only option
that lets multiple firms watch the same fleet, and keeps the data on our
infrastructure. Its weakness — isolation by configuration — is real and mitigable by
treating the RBAC and index-restriction config as security-critical: reviewed,
version-controlled, and tested by an access-attempt test rather than by inspection. If a
firm requires (c), the egress analysis in [01](01-threat-model.md) needs redoing before
agreeing, not after.

**This needs an owner.** It is the one decision here that is as much legal and
commercial as technical — the answer depends on what the MSSP contract says about data
location and retention, and no amount of architecture settles that. It blocks MSSP
onboarding but not M0: deploy single-tenant, add the tenancy model before any external
party gets access.

## Q12 — Wazuh 5.0 migrates the ruleset from XML to YAML

Wazuh 5.0 replaces the analysisd XML decoder/rule engine with a new engine using
YAML-based decoders and rules and an ECS-normalized common schema *(secondary — from
Wazuh's own GitHub issues on the migration; not verified against a 5.0 release note,
and the main-branch documentation no longer lists `analysisd.decoder_order_size`,
which is consistent with the rewrite)*.

Every rule snippet in [03](03-detection.md) is 4.x XML. If the fleet lands on 5.x, the
rules carry a rewrite cost, and the specific primitives this design leans on —
`frequency` + `timeframe`, `if_matched_sid`, `same_field` on dynamic fields — need
equivalents confirmed in the new engine. `same_field` is the one to check first, since
D2, D10's tripwire, and D11 all depend on it and the ECS normalization may change field
names underneath the flattened schema.

Unresolved: which major version to target. Targeting 4.x means a known-good design and
a migration later; targeting 5.x means designing against something less documented and
less field-proven.

**Recommendation:** build M0–M2 against 4.x, because the primitives are verified and
`wazuh-logtest` gives a tested path today — but keep the rule set small and generated
from a single source of truth rather than hand-written, so a migration is a
re-render rather than a rewrite. Price the migration before the rule count gets large.
Needs an owner to track the 5.0 release and confirm the primitives.

## Q13 — Evaluate Adrian before M1 starts *(blocking M1)*

[`secureagentics/adrian`](https://github.com/secureagentics/adrian) is a runtime
AI-agent security tool with a native Claude Code plugin, detecting "malicious,
misaligned, or out-of-remit behaviour" ([06](06-prior-art.md)). It is the closest
overlap found, and the assessment in that document rests on a one-line description
rather than on reading it.

Unresolved: does it already cover M1 and M2's ground? The provisional read is that
it is per-session, reasoning-trace-inclusive and standalone, where this is
fleet-level, action-only and SIEM-native — but that distinction is exactly the kind
that evaporates on contact with the actual code.

**Recommendation: half a day, before M1 starts, alongside Q2.** Three outcomes are
all acceptable and one is not. Acceptable: it does not fit, and we build; it fits
well, and we adopt it and contribute the Rule-of-Two and provenance layers upstream;
it partly fits, and `ambitd` narrows to the gap. Not acceptable: building the whole
thing and discovering the overlap at M3. Needs an owner, and the same person should
take Q2 since both are build-versus-adopt calls on the same milestone.
