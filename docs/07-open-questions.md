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

## Q2 — Build `mcp-interpose` or adopt an existing gateway? *(blocking M1)*

Several open-source MCP gateways already do interception, per-tool allowlists,
argument/result guardrails, and audit trails ([06](06-prior-art.md)). Our unique
need is narrow: metadata hashing, baseline diffing, and emission in our event
schema.

Options: write a minimal purpose-built interposer; fork a gateway; write a plugin
for one.

**Recommendation:** spend two days evaluating lasso-security/mcp-gateway and
enkryptai/secure-mcp-gateway against our requirements before writing anything. A
plugin is the right shape if either has a plugin surface. The failure mode to avoid
is a half-built gateway that needs auth, multi-tenancy, and transport handling we
did not plan for. Needs an owner and a decision, not a default.

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
[04](04-data-model.md), which are engineering guesses and not a compliance
position.

## Q4 — Who reviews the queue? *(blocking M2 exit)*

Layers 2 and 3 produce alerts that need human judgment, and M2's exit criteria
require reviewing every would-have-blocked event. That is a standing operational
cost, and the system's usefulness is capped by it: a queue nobody reads is a
detector nobody has.

Unresolved: who owns it, what the expected daily volume is, what the escalation path
is, and what happens to the promotion ladder if review capacity does not exist. If
the answer is "nobody," M3 should be reconsidered — enforcement without review is a
gate whose false positives nobody learns about.

## Q5 — Does `agentd` handle non-Claude-Code agents?

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
Every member of that set is a potential fleet-wide work stoppage if `agentd` has a
bug.

Unresolved: whether the set should start empty and grow, and whether "fail closed"
should mean `deny` or `ask` — `ask` degrades to a human decision rather than a hard
stop, which may be the better failure mode for all of them.

**Recommendation:** fail-closed means `ask`, not `deny`, for the whole set. A
developer answering a prompt during an `agentd` outage is a far better failure mode
than a blocked task with an opaque reason.

## Q8 — Policy bundle signing and key management.

`agentd` must refuse unsigned or downgraded bundles ([02](02-architecture.md)), which
means a signing key, a rotation story, and a trust root on every endpoint. Reuse the
existing MDM trust root if there is one, or run a separate signing chain.

Not blocking until M3, but it needs an owner before M3 starts, because retrofitting
signing onto a deployed unsigned-bundle system is worse than doing it once.

## Q9 — Naming.

`agentd`, `mcp-interpose`, `fleet` are placeholders from this design pass. Worth ten
minutes before there are import paths and config keys named after them.

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
