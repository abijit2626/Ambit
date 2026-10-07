# 02 — Architecture

## Shape

```
  ENDPOINT (untrusted)                          WAZUH (fleet plane)
  ┌────────────────────────────────────┐        ┌──────────────────────────────────┐
  │  Claude Code                       │        │  wazuh-manager                   │
  │    │ hooks (type: http →           │        │   · analysisd: custom rules      │
  │    │        127.0.0.1)             │        │     (>=100000), correlation      │
  │    │ OTLP (metrics/logs/traces)    │        │   · FIM/syscheck alerts          │
  │    ▼                               │        │   · SCA policy results           │
  │  ┌──────────────────────────────┐  │        │   · agent connect/disconnect     │
  │  │ ambitd                       │  │        │   · active response dispatch     │
  │  │  · hook endpoint (SYNC)      │  │        │   · MITRE ATT&CK tagging         │
  │  │  · OTLP receiver (async)     │  │        │        │                         │
  │  │  · R2 bit accounting         │  │        │        ▼                         │
  │  │  · provenance intersection   │  │        │  wazuh-indexer  ← alerts only    │
  │  │  · THE GATE (verdict here)   │  │        │  wazuh-dashboard                 │
  │  │  · redaction + filtering     │  │        │        │                         │
  │  └────────┬─────────────────────┘  │        │        ▼                         │
  │           │                        │        │  RBAC / agent groups → MSSP      │
  │           ▼ JSON lines             │        └──────────────────────────────────┘
  │  /var/log/ambit/events.jsonl ──────┼──► wazuh-agent (log_format json)
  │           │                        │        authenticated, bidirectional
  │           ▼                        │
  │  local spool (full trajectory,     │        managed settings (MDM or
  │  investigation pull / object store)│        server-managed) deliver hook,
  │                                    │        sandbox, and OTel config at
  │  ┌──────────────────────────────┐  │        highest precedence
  │  │ mcp-interpose                │  │
  │  └──────────┬───────────────────┘  │
  └─────────────┼──────────────────────┘
                ▼  MCP servers (untrusted)
```

Three components. `ambitd` and `mcp-interpose` on the endpoint, and **Wazuh as the
fleet plane** — manager, indexer, dashboard.

## Division of labour: what is in the synchronous path

**Wazuh is not in the synchronous path.** This is the load-bearing constraint of
the whole design and everything below follows from it.

`PreToolUse` needs a verdict in single-digit milliseconds ([latency
budget](#latency-budget-and-failure-modes)). A SIEM cannot do that — Wazuh's
analysisd is a batch correlation engine reading a log tail, with alerting latency
in seconds at best and no path to return a decision to the process that emitted
the event. Asking it to gate a tool call would be a category error.

So:

| Concern | Where | Why |
| --- | --- | --- |
| Rule-of-Two bit accounting | **ambitd** | Needs live per-session state |
| Provenance fingerprint intersection | **ambitd** | Needs the session's ingest fingerprint set in memory |
| The gate (`allow` / `deny` / `ask`) | **ambitd** | Must return a verdict inline, in ms |
| Goal-drift scoring | **ambitd**, async | Needs the session's declared objective and action history |
| Cross-event correlation within an endpoint | **Wazuh rules** | `frequency` + `timeframe` does this natively |
| Cross-endpoint and cross-session correlation | **Wazuh rules** | Manager sees the whole fleet |
| Event store, retention, archiving | **Wazuh** | It is a SIEM; this is its job |
| Alerting and the review queue | **Wazuh** | Dashboard, RBAC, MITRE tagging |
| Enrollment and heartbeat | **Wazuh** | Agent registration and disconnect alerting, native |
| Config tamper detection | **Wazuh FIM** | syscheck, native |
| Managed-settings assertion | **Wazuh SCA** | Policy-as-YAML, native |
| Containment | **Wazuh active response** | Async and coarse — never a gate |

**Events reach Wazuh already carrying the verdict and the provenance edge.**
`ambitd` has already decided; Wazuh correlates, alerts, stores, and presents. It
never re-derives a decision, and it never blocks one.

## Transport: JSON lines, no custom decoders

`ambitd` appends normalized events as single-line JSON to a local file. The Wazuh
agent tails it:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/ambit/events.jsonl</location>
  <label key="ambit.stream">ambitd</label>
</localfile>
```

`log_format json` is documented as "used for single-line JSON files and allows for
customized labels to be added to JSON events." Wazuh's built-in JSON decoder
extracts every key as a **dynamic field** addressable from rules — no custom
decoder to write or maintain. The shipped ruleset addresses nested JSON with dot
notation (`aws.httpRequest.clientIp`, `win.eventdata.targetUserName`), so nesting
is not the obstacle; see [04](04-data-model.md) for the constraint that actually
drives the flattened schema.

`only-future-events` and `age` are available if spool replay after an outage would
otherwise flood the manager — relevant given `ambitd` spools locally when the
manager is unreachable.

## Interception points

### Endpoint: Claude Code

Unchanged from the pre-Wazuh design. All verified against `code.claude.com`.

Claude Code fires hooks at 33 events. A hook can be `type: "http"`, which POSTs the
event JSON to a URL and reads the decision from the response body. Pointed at
`127.0.0.1`, this gives `ambitd` a synchronous decision point with no process spawn
per event.

| Event | Use | Can block? |
| --- | --- | --- |
| `PreToolUse` | The enforcement point. Gets `tool_name`, `tool_input`, `tool_use_id`. Returns `permissionDecision`: `allow` / `deny` / `block`. | **Yes** |
| `PostToolUse` | The observation point. Adds `tool_result` — where untrusted content enters and provenance ingest is recorded. | No |
| `PostToolUseFailure` | Same, with `tool_error`. Blocked-attempt signal. | No |
| `UserPromptSubmit` | Captures `user_input` — the declared objective goal-drift scoring measures against. | Yes |
| `PermissionRequest` | Fires when a call needs a permission decision; returns `decision`. | No (use `decision`) |
| `PermissionDenied` | Fires when auto mode denies a call. Attack-attempt signal. | No |
| `SessionStart` | Session provenance: `permission_mode`, `cwd`, `model`. | No |
| `InstructionsLoaded` | Fires when a `CLAUDE.md` or `.claude/rules/*.md` loads, with `file_path` and `load_reason`. **A poisoned `CLAUDE.md` in a cloned repo is an injection vector and this is the only event that reports it.** | No |
| `ConfigChange` | Settings changed mid-session, with `config_source`. | No |
| `FileChanged` | Watched file changed on disk. | No |
| `SubagentStart` / `SubagentStop` | Subagent subtree scoping for provenance. | No |
| `Elicitation` / `ElicitationResult` | MCP server requesting user input mid-call. | Elicitation: yes |
| `PreCompact` / `PostCompact` | Context compaction — a session boundary question for R2 state. See [03](03-detection.md#layer-1--rule-of-two-accounting). | No |

Two ordering facts the design depends on:

- The pipeline is `PreToolUse` hook → deny rules → allow rules → ask rules →
  permission mode → `canUseTool` → `PostToolUse`. A hook exiting with code 2 stops
  the call *before* permission rules are evaluated.
- **Hook decisions do not bypass permission rules.** A matching `deny` rule blocks
  regardless of a hook returning `allow`; a matching `ask` rule still prompts.
  Deny-first precedence is preserved, including managed-settings deny rules. So
  `ambitd` cannot *widen* access, only narrow it — it is fail-safe in the widening
  direction by construction.

### Endpoint: OpenTelemetry

`CLAUDE_CODE_ENABLE_TELEMETRY=1` plus OTLP config. Gives `tool_decision` events
(`tool_use_id`, `tool_name`, `decision`, `source`), `tool_result` events,
`mcp_server.name` / `mcp_tool.name` attribution, and spans. Correlation keys:
`session.id`, `prompt.id`, `tool_use_id`, `event.sequence`.

Content is gated and off by default: `OTEL_LOG_TOOL_DETAILS=1` for arguments,
`OTEL_LOG_TOOL_CONTENT=1` for output, `OTEL_LOG_RAW_API_BODIES=1` for full bodies.
Default content cap 60 KB, tunable with `CLAUDE_CODE_OTEL_CONTENT_MAX_LENGTH`.

OTel goes to `ambitd`, **not** to Wazuh. It is the content-rich stream and the
full-trajectory source; almost none of it should reach the SIEM
([04](04-data-model.md)). Its value here is that its destination is lockable in
managed settings with developer-set variables removed, making it a
tamper-resistant second stream independent of the hook path.

**Encoding: `http/json` on port 4318.** Claude Code supports `grpc`,
`http/protobuf` and `http/json`, and `http/json` is the only one decodable with
the Go standard library. The alternatives would pull grpc and protobuf runtimes
into a daemon that ships to developer endpoints and otherwise has zero
dependencies — a large supply-chain surface to add to a security tool, and one
whose whole job is not being the thing that compromises the endpoint. Port 4318 is
the OTLP/HTTP default; **4317 is gRPC** and is the wrong port for this receiver.

`ambitd` answers **415** on a protobuf body rather than failing to parse it, and
reports `degraded` health when any export is rejected. A silent decode failure
here would look like "OTel is configured" while nothing was ever received, which
is precisely the blind spot the second stream exists to close. SCA checks 10006
and 10008 assert the endpoint and the protocol so the misconfiguration is caught
before it reaches an endpoint.

**What the second stream is actually for.** Not content — the hook stream carries
the security-relevant slice with better structure. It is for the **discrepancy**:
the hook endpoint dies with `ambitd`, while OTel's destination is pinned in
managed settings. One stream reporting tool calls while the other is silent means
a collection path has stopped, which is what suppression looks like from the
inside. `ambitd` counts tool calls on both paths and reports `degraded` when
exactly one is silent; both quiet is an idle endpoint, not a signal.

The comparison is deliberately coarse — "one silent", not a ratio. The two streams
legitimately see different things: the hook path sees every subscribed event while
OTel emits on its own schedule and behind content gates. Tightening this into a
ratio threshold needs M0 baseline data, not a guess.

### Endpoint: MCP interposer

Hooks see tool *calls*, not the tool *descriptions and schemas* the server
advertised — which is the tool-poisoning vector — and cannot tell that a server's
advertised surface changed between approval and use.

`mcp-interpose` is configured as the server command in `.mcp.json`, wrapping the
real server. It sees `tools/list` responses, call arguments, and results. Its jobs:

1. Hash every tool's name, description, and input schema; compare against the
   approved baseline each session. Any delta is a rug-pull candidate (D4).
2. Scan description and schema text for instruction-shaped language and for
   references to other servers' tools (the shadowing signature, D5).
3. Record results as provenance ingest with the server's trust label.
4. Carry MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
   `openWorldHint`) into the event stream as *inputs to policy*, never as
   authority. The spec states these are hints and that clients should not trust
   them when the server itself is untrusted. So: `openWorldHint` classifies a
   result as untrusted ingest and `destructiveHint` raises required approval, but a
   server claiming `readOnlyHint: true` earns no relaxation. **Annotations may only
   make policy stricter.**

**Implementation status.** Jobs 1, 2 and 4 are built: `cmd/mcp-interpose` wraps one
server per `.mcp.json` entry, hashes each tool's name, description and input schema
against an approved baseline (`internal/baseline`), scans the advertised text
(`internal/toolscan`), and emits `mcp_list` events through `ambitd`. Job 3 — recording
results as provenance ingest — lands with M2's provenance engine rather than here. The
reason is double counting: the hook path already carries every MCP call and its result
with `tool_mcp_server` and `tool_mcp_tool` populated, and the ingest set, the taint
labels and the edges those results would attach to are M2 structures that do not exist
yet. Emitting a second copy of each call now would inflate the M0 baseline and give a
reviewer two records of one action. What the interposer does supply in the meantime is
a per-server count of the calls it observed, which corroborates its own stream against
the hook stream the way D7's OTel check corroborates the other two.

**One correlation gap, stated rather than papered over.** MCP carries no Claude Code
session id, so an `mcp_list` event usually has none: the interposer records the client's
self-reported name and version, its own pid and ppid, and honours `AMBIT_SESSION_ID` or
`CLAUDE_SESSION_ID` when something sets them, but it does not invent an id. An event
correlated to the wrong session is worse than one correlated to none. Correlation is by
endpoint, server and time until a documented way to pass the id exists.

### Wazuh: FIM / syscheck — covers most of D6

Config tamper detection, native. One documented constraint shapes the config:
**"Real time only works with directories, not individual files."** So watch the
directory and narrow with `restrict`, rather than naming the file:

```xml
<syscheck>
  <directories realtime="yes" check_all="yes" report_changes="yes"
               whodata="yes" restrict="settings\.json$|settings\.local\.json$"
               tags="ambit,claude-settings">/home/*/.claude</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes"
               whodata="yes" restrict="\.mcp\.json$"
               tags="ambit,mcp-config">/home/*/src</directories>
</syscheck>
```

`whodata` is worth the setup cost here: it reports *which user and process*
modified the file, via Linux Audit or eBPF. For adversary A1 — malware editing
agent config — "which process wrote this" is the whole question. `realtime` alone
reports only that it changed.

`report_changes` gives the content diff, limited to text files, bounded by
`diff_size_limit` (default 50 MB). Settings files are small and text, so diffs are
cheap and directly reviewable.

**What FIM does not cover:** in-session config changes that never touch disk, and
settings precedence. A developer passing `--settings` on the command line, or a
project-level file that does not exist yet, will not appear as a modification to a
watched path. Claude Code's `ConfigChange` hook covers the in-session case and
reaches Wazuh through `ambitd`. So D6 is FIM *plus* `ConfigChange`, and neither
alone is sufficient.

### Wazuh: SCA — asserting the managed-settings bundle

New in this revision, and the piece that makes the managed-settings anchor
*verifiable* rather than assumed. Everything in [the managed settings
section](#managed-settings--the-anchor) is a claim about endpoint state. SCA turns
each claim into a check that runs on schedule and alerts on drift.

SCA policies are YAML. Checks use rule prefixes `f:` (file), `d:` (directory), `p:`
(process), `c:` (command output), `r:` (Windows registry), with `->` for content
matching, `r:` for regex, `n:` for numeric comparison, `&&` to chain, `not` to
negate, and a per-check `condition` of `all`, `any`, or `none`. `regex_type` selects
`osregex` (default) or `pcre2`.

```yaml
policy:
  id: "ambit_managed_settings"
  file: "ambit_managed_settings.yml"
  name: "ambit managed settings assertions"
  description: "Asserts the Claude Code managed-settings bundle is present and correct"
  regex_type: "pcre2"

checks:
  - id: 10001
    title: "Managed settings file is present"
    condition: all
    rules:
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json'

  - id: 10002
    title: "bypassPermissions mode is disabled"
    rationale: "bypassPermissions is the invocation mode used by the s1ngularity malware pattern."
    remediation: "Restore the managed settings bundle via MDM."
    condition: all
    rules:
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json -> r:"disableBypassPermissionsMode"\s*:\s*"disable"'

  - id: 10003
    title: "Sandbox is enabled and fails closed when unavailable"
    condition: all
    rules:
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json -> r:"enabled"\s*:\s*true'
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json -> r:"failIfUnavailable"\s*:\s*true'
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json -> r:"allowUnsandboxedCommands"\s*:\s*false'

  - id: 10004
    title: "Egress allowlist is locked to managed domains"
    condition: all
    rules:
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json -> r:"allowManagedDomainsOnly"\s*:\s*true'

  - id: 10005
    title: "ambitd is running"
    condition: all
    rules:
      - 'p:ambitd'

  - id: 10006
    title: "OTel destination is pinned to localhost"
    condition: all
    rules:
      - 'f:/Library/Application Support/ClaudeCode/managed-settings.json -> r:OTEL_EXPORTER_OTLP_ENDPOINT.*127\.0\.0\.1'
```

**Honest limitation.** SCA regex-matches file *text*; it is not a JSON-aware
assertion. A semantically equivalent but differently-formatted bundle (key order,
whitespace, a value expressed as `"disable"` versus some future accepted synonym)
can fail a check that should pass, or — worse — pass a check that should fail, if a
key appears inside a comment or an unrelated nested object. Two mitigations: pin
the bundle's exact serialization at build time so the text is deterministic, and
add `c:` checks that shell out to a small verifier for anything where text matching
is genuinely ambiguous. Treat the SCA policy as a tripwire on a known-good file,
not as a parser.

`p:ambitd` (check 10005) is a weak liveness check — it confirms a process by that
name exists, nothing about whether it is functioning. It is a complement to, not a
replacement for, the event-stream evidence behind D7 and D11.

### Wazuh: agent connect/disconnect — D7 for free

The manager alerts on agent disconnection natively. Rule **504**, level 3,
`Wazuh agent disconnected`, already tagged **MITRE T1562.001** (Impair Defenses:
Disable or Modify Tools) in the shipped ruleset — which is exactly the right
technique for "someone killed the monitoring."

Tuning: `agents_disconnection_time` sets when an agent counts as disconnected and
`agents_disconnection_alert_time` sets how long after that an alert fires. The
alert-time default is `0s` (alert as soon as disconnected); with default values the
documented minimum time to produce an alert is 2m20s.

This gives D7's *coarse* half — the endpoint went dark — with no code. It does not
give the finer half: `ambitd` dead while the Wazuh agent is alive, so the endpoint
still heartbeats while the event stream stops. That is a rule on event absence,
covered in [03](03-detection.md).

### Wazuh: active response — containment only, never a gate

Active response triggers on rule ID, level, or group and executes a script. It is
**asynchronous and coarse**: it fires after analysisd has correlated an alert,
which is seconds to minutes after the tool call it is reacting to. The tool call has
already run.

So the rule is absolute: **active response contains, it does not gate.** The inline
gate is `ambitd`'s and only `ambitd`'s.

Reasonable containment actions on D1 or D3 firing:

- Revoke the endpoint's git and cloud credentials (the useful one — it invalidates
  what was probably already stolen, and limits what can be done with it next)
- Disable the agent installation / write a kill-switch file `ambitd` reads to drop
  to deny-by-default
- Isolate the host at the network layer, where endpoint management supports it

Wazuh's own documentation warns that "poor implementation of rules and responses
might increase the vulnerability of an endpoint," and that caution applies with
force here: every one of these actions is disruptive, and each is triggered by a
detector with a non-zero false-positive rate. Start with credential revocation only,
require a reviewed alert for anything that stops a developer working, and see
[Latency budget and failure modes](#latency-budget-and-failure-modes) for how
`ambitd` itself fails.

### Managed settings — the anchor

Everything above is configuration, and configuration on a compromised endpoint is
attacker-editable. Managed settings (MDM-delivered file, or server-managed settings
on claude.ai) sit at the highest precedence: **no other level, including
command-line arguments, overrides a managed permission rule**, and managed hooks
cannot be disabled by user or project settings.

```json
{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4317"
  },
  "permissions": { "disableBypassPermissionsMode": "disable" },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "network": { "allowManagedDomainsOnly": true, "allowedDomains": ["..."] }
  },
  "hooks": { "PreToolUse": [ { "matcher": ".*", "hooks": [
    { "type": "http", "url": "http://127.0.0.1:7777/pre-tool-use" } ] } ] }
}
```

`allowManagedDomainsOnly` blocks non-allowed domains outright instead of prompting
and honors only managed entries. `failIfUnavailable` refuses to start rather than
silently running unsandboxed. `disableBypassPermissionsMode` is the direct counter
to the s1ngularity invocation pattern. SCA above asserts all of it is actually
there.

## Trust boundaries — reworked for an authenticated agent

The pre-Wazuh design specified a **write-only, one-way ingest endpoint**, on the
reasoning that an agent able to `POST` to its own monitor can poison its own audit
trail. That reasoning was sound and it no longer describes what we are building.

**The Wazuh agent authenticates to the manager over a bidirectional channel.** That
channel carries enrollment, centralized configuration, SCA policy distribution,
remote commands, and active-response dispatch. It is not an ingest pipe. This
changes the threat surface in two directions and both need stating:

**Direction 1 — the manager can command the endpoint.** Active response means the
manager can execute scripts on every enrolled endpoint. A compromised Wazuh manager
is therefore a fleet-wide code-execution primitive, which the pre-Wazuh design did
not have. With an MSSP in the picture ([01](01-threat-model.md)), so is a
compromised or malicious MSSP operator. Mitigations:

- Active response scripts are **allowlisted on the endpoint**, not supplied by the
  manager. The manager names a command; it does not ship one.
- The allowlisted set is minimal, reviewed, and each entry is individually
  justifiable as containment ([above](#wazuh-active-response--containment-only-never-a-gate)).
- Any action that stops a developer working requires a reviewed alert, not an
  automatic trigger.
- MSSP roles get **no active-response dispatch permission** — containment is ours
  to execute on their recommendation. This is a policy control, and it depends
  entirely on the [tenancy model](#tenancy-for-third-party-monitoring) holding.

**Direction 2 — the endpoint's agent credential is on the endpoint.** Adversary A1
has local code execution and can therefore read the Wazuh agent's enrollment key
and speak to the manager as that agent: injecting fabricated events, or flooding to
bury real ones. This is a genuine regression against the write-only design and
there is no clean fix on a compromised endpoint. Partial mitigations: per-agent keys
so forgery is scoped to one endpoint rather than the fleet; rate and volume
baselining per agent so a flood is itself an alert; and treating the `ambitd` event
stream and the FIM/SCA/OTel streams as mutually corroborating, since forging all of
them consistently is meaningfully harder than forging one.

Full table:

| Boundary | Direction | Control |
| --- | --- | --- |
| MCP server → interposer | inbound, untrusted | Metadata hashing, description scanning, results labelled untrusted |
| Claude Code → ambitd | inbound, semi-trusted | Structurally cannot widen permissions (deny-first precedence) |
| ambitd → events.jsonl → wazuh-agent | local, same host | Filtered and redacted at source; file is append-only to `ambitd`, read-only to the Wazuh agent |
| wazuh-agent ↔ wazuh-manager | **bidirectional, authenticated** | Per-agent enrollment keys; endpoint-side active-response allowlist; per-agent volume baselining |
| wazuh-manager → MSSP | outbound, contractual | RBAC + agent groups + index restrictions; digests-only; no AR dispatch. See [Tenancy](#tenancy-for-third-party-monitoring) |
| fleet → ambitd policy | inbound policy | Signed policy bundles, version-pinned; `ambitd` refuses unsigned or downgraded bundles. **Not delivered over the Wazuh channel** — separate path, separate trust root |
| Developer/malware → settings | adversarial | Managed settings outrank all; FIM + SCA + `ConfigChange` report attempts |

Note the last-but-one row. Policy bundles that decide what `ambitd` denies are
**deliberately not** distributed through Wazuh's centralized-configuration channel,
even though it exists and would be convenient. Doing so would make the manager — and
whoever has manager access, including an MSSP — able to rewrite the inline gate.
Keeping the enforcement path's trust root separate from the monitoring path's is
worth the extra plumbing.

## Tenancy for third-party monitoring

Every restriction placed on a monitoring firm — in [01](01-threat-model.md) and in the
table above — is a policy control resting on a tenancy model. Wazuh is not natively
multi-tenant the way commercial SIEMs are, so the model chosen decides whether those
restrictions are enforced or only intended. Until one is chosen and its configuration
is tested, treat them as intentions.

| Model | For | Against |
| --- | --- | --- |
| **a. Manager per tenant** | Strongest isolation of rules, agent configuration and active-response scope; one firm's rule changes cannot affect another's. | Agents are partitioned by firm, so two firms cannot watch the same fleet. Some internal Wazuh metadata is shared when several managers feed one indexer, so isolation is not clean there either. Heaviest to operate. |
| **b. One manager: agent groups, API RBAC, index-level restrictions** | One deployment. The supported path: agent group labels appear on every indexed alert, which is what index restrictions key on. Several firms can watch the same agents with different scopes. | Isolation is a configuration property, so a misconfigured role is a silent data leak. Rule definitions are global. Withholding active-response dispatch is an RBAC permission, not an architectural boundary. |
| **c. Forward alerts into each firm's own Wazuh** | Their analysts work in their own tooling; no access to our manager, so the active-response concern disappears. | Changes the egress posture: alert data is exported to infrastructure we do not operate, digests-only guarantees become contract terms rather than properties of our deployment, and revocation stops being unilateral. Breaks the digest-resolution workflow. |

**Recommendation: (b), with (a) held in reserve, and (c) only if a firm's own platform
is a hard requirement of the engagement** — in which case the egress analysis in
[01](01-threat-model.md) must be redone before agreeing. Treat the RBAC and index
restriction configuration as security-critical: version-controlled, reviewed, and
tested by an access-attempt test rather than by inspection.

The decision is as much legal and commercial as technical — it depends on what the
monitoring contract says about data location and retention — and it needs an owner.
It gates onboarding any external party, not deploying internally: run single-tenant
first.

## Why a local daemon rather than hooks calling Wazuh directly

Beyond the fact that Wazuh has no mechanism to return a decision to a hook:
`PreToolUse` is synchronous on **every** tool call. A round trip to a central
service puts fleet-wide network latency and availability in the critical path of
every file read on every developer's machine. When that service is slow or down you
must choose between failing open (the gate silently stops existing) and failing
closed (every developer stops working at once). Neither is acceptable as a steady
state.

`ambitd` decides locally from a cached signed bundle, targets single-digit
milliseconds, and streams to Wazuh asynchronously. Wazuh's availability then affects
detection latency, not developer throughput.

## Latency budget and failure modes

| Path | Budget | On timeout |
| --- | --- | --- |
| `PreToolUse` → decision | p99 ≤ 5 ms, hard ceiling 250 ms | See fail policy below |
| `PostToolUse` ingest | fire-and-forget, never blocks | Drop to local spool |
| Append to `events.jsonl` | fire-and-forget | Spool; never block the hook path on disk |
| Async detectors (goal drift) | seconds | Advisory only; never gates inline |
| Wazuh agent → manager | minutes | Wazuh agent buffers; `ambitd` rotates `events.jsonl` with a bounded cap |

**Fail policy on `ambitd` unavailability.** Split by action class, not global:

- **Fail closed** for a small, enumerated set of high-impact classes: writes to
  credential paths, outbound network from Bash, `git push`, MCP tools annotated
  destructive, writes outside the working directory. "Fail closed" means `ask`,
  not `deny`: a developer answering a prompt during an `ambitd` outage is a far
  better failure mode than a blocked task with an opaque reason.
- **Fail open** for everything else, and **emit a fail-open record every time**. A
  run of fail-opens is itself an alert (D11) — it is what suppressing the daemon
  looks like.

A bug in `ambitd` must not halt every developer at once, or the system gets
disabled. A narrow fail-closed set keeps catastrophic actions gated while keeping
the blast radius of our own outage survivable.

## Tamper resistance, honestly

`ambitd` runs as the user on a machine adversary A1 fully controls. It can be
killed. The mitigations are not "make it unkillable":

1. **Policy above the attacker's reach.** Managed settings cannot be overridden by
   CLI args, project settings, or user settings. The sandbox, the egress allowlist,
   and `disableBypassPermissionsMode` hold even with `ambitd` dead — and SCA
   verifies they are still there.
2. **Silence is a signal.** Wazuh knows the enrolled roster and alerts on
   disconnection natively (rule 504, T1562.001). An endpoint that goes quiet while
   still checked into work is an alert.
3. **Four independent streams.** `ambitd` events (killable with the daemon), FIM,
   SCA, and agent connectivity — the last three are the Wazuh agent's, a separate
   process. Losing one while the others continue is a high-signal discrepancy, and
   it is the discrepancy rather than any single stream that makes suppression
   visible.

Residual risk, restated: this makes endpoint compromise visible and expensive, not
impossible. An attacker who kills both `ambitd` and the Wazuh agent, or who forges
a plausible stream with the stolen enrollment key, degrades our visibility. We
detect the *absence* and the *inconsistency*; we do not prevent either.
