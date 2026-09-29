# 06 — Prior art, reuse, and non-goals

The single biggest risk to this project is building something that already exists.
Claude Code in particular ships far more security machinery than is commonly
realized, and a naive version of this system would reimplement most of it worse.

## What Claude Code already provides

Verified against the official docs at `code.claude.com` during research.

### Enforcement

| Mechanism | What it does |
| --- | --- |
| **Sandboxed Bash** | OS-enforced filesystem and network isolation for Bash/PowerShell/Monitor commands *and all child processes*. Seatbelt on macOS, bubblewrap on Linux/WSL2. Enforced by the OS on the running process, so it holds regardless of what the model chose to run and even if an allowed command does more than its name suggests. |
| **Network isolation** | A proxy outside the sandbox enforces a domain allowlist. No domains pre-allowed by default. `strictAllowlist` denies instead of prompting; `allowManagedDomainsOnly` honors only managed entries and blocks the rest outright. `deniedDomains` blocks even through a broader wildcard. |
| **Filesystem isolation** | `allowRead`/`denyRead`/`allowWrite`/`denyWrite`; working-directory boundary by default. |
| **Credential masking** | `sandbox.credentials` with `mode: "mask"` shows the command a per-session sentinel and has the proxy substitute the real value only on requests to `injectHosts`. The command and its logs never hold the credential. Requires `network.tlsTerminate`. `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` strips credentials from all subprocesses. |
| **Permission rules** | Deny/ask/allow across every tool. Managed settings outrank every other scope including CLI arguments. **Hook decisions cannot bypass deny rules.** |
| **`disableBypassPermissionsMode`** | Managed setting that blocks `bypassPermissions` outright — the direct counter to the s1ngularity invocation pattern. |
| **Auto-mode classifier** | A separate classifier model reviews actions in auto mode; explicit ask/deny rules still apply; organizations can disable auto mode. |
| **Hooks** | 33 events. `PreToolUse` blocks before permission rules are evaluated. |
| **Isolated web fetch context** | WebFetch uses a separate context window specifically to avoid injecting fetched content into the main one. |
| **Trust verification** | First run in a codebase and each new MCP server require trust acceptance — though **disabled under `-p`**, which is exactly the non-interactive path A1 uses. |

### Observation

OpenTelemetry metrics, logs, and traces. `tool_decision` events (with `decision`
and `source`), `tool_result` events, `mcp_server.name` / `mcp_tool.name`
attribution, span hierarchy from interaction to tool execution. Content gated
behind `OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_TOOL_CONTENT`, and
`OTEL_LOG_RAW_API_BODIES`. **Destination lockable in managed settings, with
developer-set variables removed to prevent redirection** — which is what makes it
a tamper-resistant second stream.

### The gap

What Claude Code does *not* do, and will not without knowing your fleet:

1. **No provenance.** Nothing connects an untrusted ingest to a later action.
2. **No Rule-of-Two accounting.** The bits are observable; nothing tracks them.
3. **No cross-session or cross-endpoint state.** Every session is an island.
4. **No goal-relevance scoring.** Nothing compares an action to the stated task.
5. **No MCP metadata baselining.** Trust verification is one-time per server, so
   a rug pull after approval is invisible.
6. **Telemetry is not detection.** OTel emits; nothing decides.

**Design consequence, and the most important sentence in this document:** we
*configure and consume* Claude Code's primitives. We do not reimplement the
sandbox, the egress proxy, credential masking, or permission evaluation. Anything
we build that overlaps those is a bug in this design.

## What else exists

### MCP security tooling

**mcp-scan / Snyk Agent Scan** (Invariant Labs, ETH Zurich spin-out; acquired by
Snyk June 2025). Apache-2.0 but closed to external contributions. Discovers and
scans local agent components — agents, skills, MCP servers — for prompt injection,
tool poisoning, tool shadowing, toxic flows, malware payloads, and credential
handling issues; v0.6+ reports 14 scored risk indicators. Supports Claude Code on
macOS, Linux, and Windows. *(Proxy/runtime-monitoring mode is reported by secondary
sources but was not confirmed in the primary repo docs — unverified.)*

**Reuse decision:** consume it, do not rebuild it. Static analysis of tool
descriptions is its job and it does it better than we would. `mcp-interpose`
handles what a scanner structurally cannot: continuous *runtime* capture of what
each server advertised *this session*, and diffing against the approved baseline.
If Agent Scan exposes machine-readable verdicts, ingest them as events.

**MCP gateways** (lasso-security/mcp-gateway, enkryptai/secure-mcp-gateway,
reaatech/mcp-gateway, Bifrost). Multi-tenant auth, rate limiting, per-tool
allowlists, argument and result guardrails, audit trails. Genuinely overlapping
with `mcp-interpose`.

**Reuse decision:** evaluate before writing `mcp-interpose`. If one of these is a
good host, our contribution is a plugin that does metadata hashing and baseline
diffing plus event emission in our schema — not another gateway. Flagged in
[07](07-open-questions.md) as a real build-vs-adopt decision, not a formality.

### The fleet plane: Wazuh

**Decision made: Wazuh is the fleet plane.** Not evaluated here — applied. What
matters for this document is what that deletes from our scope.

| Capability | Wazuh provides | Our remaining work |
| --- | --- | --- |
| Event store, retention, archiving | indexer | choose retention; keep `logall_json` off |
| Alerting, severity, review queue | manager + dashboard | write rules and runbooks |
| Enrollment, endpoint roster | agent registration | enrol the cohort |
| Heartbeat / agent liveness | **rule 504, `Wazuh agent disconnected`, level 3, already tagged MITRE T1562.001** in the shipped ruleset | tune `agents_disconnection_time` / `agents_disconnection_alert_time`; add the finer `ambitd`-died case |
| Log ingestion | `localfile` with `log_format json`; built-in JSON decoder yields addressable dynamic fields | write `events.jsonl`; **no custom decoder** |
| Cross-event correlation | `frequency` + `timeframe` + `if_matched_sid` + `same_field` (dynamic fields only) | express D2, D10-tripwire, D11 as rules |
| Config tamper detection | FIM/syscheck with `whodata` (user + process attribution via Audit/eBPF) | watch `.claude/` and `.mcp.json` as **directories with `restrict`** — realtime does not work on individual files |
| Config assertion | SCA: YAML policies, `f:`/`d:`/`p:`/`c:`/`r:` rules, `->` content matching, `condition: all/any/none` | write the managed-settings policy (D12) |
| ATT&CK tagging | `<mitre>` block per rule | propose mappings ([03](03-detection.md)) |
| Containment | active response, triggered by rule id/level/group | **allowlist scripts on the endpoint**; containment only, never a gate |
| Multi-tenant access | RBAC + agent groups + index restrictions | resolve the model ([07](07-open-questions.md) Q11) |

**What Wazuh cannot do, and why `ambitd` still exists:** it has no mechanism to
return a verdict to the process that emitted an event, and its correlation latency is
seconds at best. The inline gate, the Rule-of-Two bit accounting, and the provenance
fingerprint intersection all need live session state and a millisecond answer. That is
the whole of our differentiated work, and it is unaffected by adopting a SIEM.

**Known constraints we design around**, all verified against 4.x documentation:

- **"An array of objects is not supported"** by the JSON decoder. This, not nesting
  depth, is what forces the flattened SIEM-bound schema ([04](04-data-model.md)).
  Nested objects addressed with dot notation are fine and the shipped ruleset uses
  them.
- `analysisd.decoder_order_size` defaults to 256 (range 32–1024). The
  `Too many fields for JSON decoder` failure mode reported by users is *dropped
  events* — silent detection loss — so event width is a security property, not just
  tidiness.
- `same_field` works on **dynamic** fields and explicitly not on static ones, which
  suits us, but it is scalar equality and cannot express the set intersection D10
  actually needs ([03](03-detection.md)).
- `logall` / `logall_json` write every event including non-alerting ones to
  `archives.log` / `archives.json`. Both default to `no`. They stay `no`.

### Directly overlapping: Adrian

[`secureagentics/adrian`](https://github.com/secureagentics/adrian) describes itself
as an open-source runtime AI-agent security tool that "monitors and controls AI
agents, catching malicious tool use, prompt injection, and policy drift in real
time, before the agent acts," analysing agent activity logs and reasoning traces to
detect "malicious, misaligned, or out-of-remit behaviour." It ships SDKs for Python
and TypeScript **and a native Claude Code plugin**.

This is the closest thing to a direct overlap found during research, and leaving it
out of a prior-art document would make that document misleading.

**Assessment, and its limits.** From the project description alone — *not* from
reading the code, which is work still owed — the differences that would justify
building this anyway are:

- **Reasoning traces vs. actions.** Adrian analyses reasoning traces alongside
  activity. The finding this whole design rests on is that chain-of-thought
  monitoring is the fragile, degrading signal and action-level monitoring is the
  durable one ([03](03-detection.md)). If Adrian's detection leans on traces, it
  inherits that fragility; if it is action-first, the overlap is larger than it
  looks.
- **Per-session vs. fleet.** Nothing in the description suggests cross-session or
  cross-endpoint correlation, which is where D2, D9 and D10 live and the reason
  Wazuh is in this design at all.
- **SIEM-native vs. standalone.** This system is built to hand a security team
  alerts in the tool they already run, with ATT&CK tags and runbooks an external
  analyst can execute. A standalone dashboard is a different product.
- **Rule-of-Two accounting and provenance edges.** No evidence either exists in
  Adrian, and they are the two mechanisms this design contributes.

**Resolved.** These four gaps were confirmed against the actual code, and a fifth,
more consequential one was found: Adrian already ships a working inline
`PreToolUse` deny path, on a ~15-second synchronous budget, driven by the same
LLM-judge classifier. The full evaluation, with file-and-line evidence and a
reproduction script, is [09](09-adrian-evaluation.md) ([07](07-open-questions.md)
Q13). Decision: build continues — the overlap is not partial, because the gap
Adrian leaves **is** the deterministic layer this project contributes, not a piece
of it.

### Defensive architecture

**CaMeL** — *Defeating Prompt Injections by Design* (arXiv:2503.18813). Dual-LLM:
a privileged LLM that plans from trusted input only and emits pseudo-Python, and a
quarantined LLM that processes untrusted data with no tool access. A custom
interpreter tracks a dataflow graph over every variable and enforces capability
policies. 77% of AgentDojo tasks with provable security.

**Relationship to this design:** CaMeL is what we would build if we controlled the
agent loop. We do not — Claude Code is a black box that emits events — so
[03](03-detection.md)'s provenance layer is an explicitly unsound approximation of
what CaMeL does soundly. Worth saying plainly rather than implying taint-tracking
guarantees we do not have. If the fleet ever runs agents we *do* build (Agent SDK),
CaMeL's architecture is the better answer for those and this system becomes their
monitor rather than their guardrail.

**Agents Rule of Two** (Meta, 31 October 2025). No more than two of: untrusted
input, sensitive data, state change / external communication — within a session.
All three requires supervision rather than autonomy. Endorsed by Simon Willison as
the best practical advice available, and the operational form of his "lethal
trifecta."

**Relationship:** [03](03-detection.md) layer 1 is a runtime implementation of it
against Claude Code's hook API. As far as the research found, nobody has built
that. It is the most concrete unbuilt thing in the plan.

**AI control** (Redwood Research; Greenblatt et al., *AI Control: Improving Safety
Despite Intentional Subversion*). Trusted monitoring, defer-to-trusted, trusted
editing, untrusted monitoring, resampling. Protocols that hold even if the model is
actively trying to subvert them.

**Relationship:** out of scope under this threat model, which assumes the model is
hijacked rather than adversarial ([01](01-threat-model.md), assumption 3). Named
because if that assumption changes, this literature — including the collusion risk
when an untrusted model monitors another instance of itself — becomes the right
frame, and layer 3's use of the model's own declared objective becomes unsound.

### Benchmarks

**AgentDojo** (ETH Zurich) — indirect prompt injection / agent hijacking. NIST
CAISI, with UK AISI, used it on Claude 3.5 Sonnet and observed attack success rise
from 11% for the strongest baseline attack to 81% for a stronger adaptive attack.
That gap is the empirical case for architecture over detection, and the reason
[03](03-detection.md) insists on testing against adapted rather than baseline
attacks.

**SHADE-Arena** (Kutasov et al., arXiv:2506.15740; Anthropic with Redwood
Research, Scale AI and others, June 2025) — benign main task plus hidden malicious
side task in a simulated workplace, scored by a monitor blind to the side task.
The benchmark layer 3 is built against.

**ControlArena** (UK AISI with Redwood Research) — control settings, model
organisms, and protocols.

**Reuse decision:** these are the regression suite ([05](05-build-plan.md) M2), not
something to reimplement. Writing our own attack corpus before exhausting these
would be wasted effort.

### Standards and guidance

**OWASP Top 10 for Agentic Applications** (published 9 December 2025). ASI01 Agent
Goal Hijack, ASI02 Tool Misuse, ASI03 Identity and Privilege Abuse, ASI04 Agentic
Supply Chain, ASI05 Unexpected Code Execution, ASI06 Context Management and
Retrieval Manipulation, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading
Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.

Use as the coverage checklist. Current mapping:

| ASI | Covered by |
| --- | --- |
| ASI01 Goal hijack | Layer 3 goal drift; layer 2 provenance |
| ASI02 Tool misuse | R2 gate; MCP annotations as policy input |
| ASI03 Identity/privilege abuse | Credential zones (B bit); credential masking (Claude Code) |
| ASI04 Supply chain | D4 metadata drift; D5 poisoned descriptions; Agent Scan ingest |
| ASI05 Unexpected code execution | Sandbox (Claude Code); D1, D3 |
| ASI06 Context manipulation | D8 poisoned instruction files; taint on `InstructionsLoaded` |
| ASI07 Inter-agent comms | D10 — **thin, M5 only** |
| ASI08 Cascading failures | **Not covered.** Gap. |
| ASI09 Human-agent trust | **Not covered** — arguably out of scope, but unexamined |
| ASI10 Rogue agents | D1, D7, heartbeat |

Two acknowledged gaps (ASI08, ASI09) rather than a claim of full coverage.

**MCP tool annotations** — `readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`. The spec states these are hints, not guarantees, and that clients
should not trust them when the server itself is untrusted. Hence the asymmetric use
in [02](02-architecture.md): annotations may only make policy stricter.

**Prompt Infection** (Lee & Tiwari, arXiv:2410.07283) — self-replicating LLM-to-LLM
injection across multi-agent systems, with more capable models spreading it more
effectively and larger systems offering more pathways. Their mitigation is LLM
tagging: marking agent-generated content so downstream agents can distinguish it
from user instructions. Motivates D10 and is a candidate control in its own right —
tagging agent-authored PR descriptions and commit messages so a downstream agent
treats them as data.

## Non-goals

Explicitly out of scope, so nobody builds them by accident:

1. **A sandbox.** Claude Code's is OS-enforced and better than anything we would
   write.
2. **An egress proxy or allowlist engine.** Exists, with managed lockdown. We
   configure and observe it.
3. **A credential vault or masking layer.** Exists.
4. **A prompt-injection classifier as the primary defense.** Prompt injection has
   no known complete fix; AgentDojo's 11% → 81% adaptive-attack result is the
   reason. Architecture and blast-radius reduction over filtering. A classifier may
   appear as one weak signal among many, never as the boundary.
5. **A static MCP scanner.** Agent Scan / mcp-scan does this. We do runtime
   baseline diffing, which is a different thing.
6. **An eval harness.** AgentDojo, SHADE-Arena, and ControlArena exist and are our
   regression suite.
7. **Model-level alignment or sabotage evaluation.** We are not evaluating models.
   We are monitoring deployed agents under the assumption that the model is
   hijacked, not scheming.
8. **Blocking on reasoning content.** The research consensus is that
   chain-of-thought monitoring is the fragile signal. We monitor actions. Reasoning
   content, where available, is at most a weak corroborating input — never a gate.
9. **SIEM functionality.** No event store, no retention engine, no alert router, no
   severity model, no review-queue UI, no enrollment service, no heartbeat tracker, no
   ATT&CK tagging infrastructure, no dashboard. Wazuh does all of it. If we find
   ourselves building a query layer over our own event store, something has gone
   wrong — the correct move is a Wazuh rule, or a scheduled job over object storage
   for the two detectors that genuinely need set operations. The one deliberate
   exception is the **local spool**, which exists because the full trajectory must not
   go to the indexer ([04](04-data-model.md)); it is cheap storage and a pull path,
   not an analytics platform.
10. **A custom Wazuh decoder.** The built-in JSON decoder gives addressable dynamic
   fields from `log_format json`. Writing a decoder would add a maintenance burden and
   a version-coupling risk for no gain; the flattened schema exists precisely so the
   built-in one suffices.
