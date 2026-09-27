# 02 — Architecture

## Shape

```
  ENDPOINT (untrusted)                        FLEET PLANE (trusted, one-way ingest)
  ┌──────────────────────────────────┐        ┌────────────────────────────────┐
  │  Claude Code                     │        │                                │
  │    │                             │        │  ingest (write-only)           │
  │    │ hooks (type: http →         │        │    │                           │
  │    │        127.0.0.1)           │        │    ▼                           │
  │    │ OTLP (metrics/logs/traces)  │        │  event store (append-only)     │
  │    ▼                             │        │    │                           │
  │  ┌────────────────────────────┐  │  push  │    ├─► correlation / detectors │
  │  │ agentd                     │──┼───────►│    ├─► MCP inventory + drift   │
  │  │  · hook endpoint (sync)    │  │        │    ├─► enrollment / heartbeat  │
  │  │  · OTLP receiver (async)   │  │        │    └─► alerting, review queue  │
  │  │  · provenance engine       │  │        │                                │
  │  │  · policy engine (local)   │  │◄───────│  policy bundles (signed)       │
  │  │  · redaction at the edge   │  │  pull  │                                │
  │  └────────────────────────────┘  │        └────────────────────────────────┘
  │    ▲                             │
  │    │ tool list / call / result    │        managed settings (MDM or
  │  ┌────────────────────────────┐  │        server-managed) deliver hook,
  │  │ mcp-interpose              │  │        sandbox, and OTel config at
  │  └──────────┬─────────────────┘  │        highest precedence
  └─────────────┼────────────────────┘
                ▼  MCP servers (untrusted)
```

Three components. `agentd` on every endpoint, `mcp-interpose` between the agent
and each MCP server, and the central `fleet` plane.

## Interception points

All of these are documented Claude Code surfaces, verified against
`code.claude.com` docs during research.

### Hooks — the synchronous control point

Claude Code fires hooks at 33 events. A hook can be `type: "http"`, which POSTs
the event JSON to a URL and reads the decision from the response body in the same
format as a command hook. Pointing that at `127.0.0.1` gives `agentd` a
synchronous decision point with no process spawn per event.

The events that matter most:

| Event | Use | Can block? |
| --- | --- | --- |
| `PreToolUse` | The enforcement point. Gets `tool_name`, `tool_input`, `tool_use_id`. Returns `permissionDecision`: `allow` / `deny` / `block`, plus a reason. | **Yes** |
| `PostToolUse` | The observation point. Adds `tool_result` — this is where untrusted content enters and where provenance ingest is recorded. | No |
| `PostToolUseFailure` | Same, with `tool_error`. Blocked-attempt signal. | No |
| `UserPromptSubmit` | Captures `user_input` — the declared objective that goal-drift scoring measures against. Can inject `additionalContext`. | Yes |
| `PermissionRequest` | Fires when a call needs a permission decision; returns `decision`. A second gate distinct from `PreToolUse`. | No (use `decision`) |
| `PermissionDenied` | Fires when auto mode denies a call. Attack-attempt signal. | No |
| `SessionStart` | Session provenance: `permission_mode`, `cwd`, `model`. | No |
| `InstructionsLoaded` | Fires when a `CLAUDE.md` or `.claude/rules/*.md` is loaded, with `file_path` and `load_reason`. **A poisoned `CLAUDE.md` in a cloned repo is an injection vector, and this is the only event that reports it.** | No |
| `ConfigChange` | Settings changed mid-session, with `config_source`. Tamper signal. | No |
| `FileChanged` | Watched file changed on disk — point it at `.env`, `.envrc`, settings files. | No |
| `SubagentStart` / `SubagentStop` | Subagent subtree scoping for provenance. | No |
| `Elicitation` / `ElicitationResult` | MCP server requesting user input mid-call. | Elicitation: yes |
| `PreCompact` / `PostCompact` | Context compaction — a session boundary question for Rule-of-Two state. See [07](07-open-questions.md). | No |

Two ordering facts that the design depends on:

- The permission pipeline is `PreToolUse` hook → deny rules → allow rules → ask
  rules → permission mode → `canUseTool` → `PostToolUse`. A hook exiting with
  code 2 stops the call *before* permission rules are evaluated.
- **Hook decisions do not bypass permission rules.** A matching `deny` rule blocks
  the call regardless of a hook returning `allow`, and a matching `ask` rule still
  prompts. Deny-first precedence is preserved, including deny rules in managed
  settings. So a compromised hook cannot widen access — it can only narrow it.
  That asymmetry is load-bearing: `agentd` is fail-safe in the widening direction
  by construction.

### OpenTelemetry — the asynchronous firehose

Enabled with `CLAUDE_CODE_ENABLE_TELEMETRY=1` plus OTLP exporter config. Gives
`tool_decision` events (`tool_use_id`, `tool_name`, `decision`, `source`),
`tool_result` events, `mcp_server.name` / `mcp_tool.name` attribution, and spans
(`claude_code.interaction` → `claude_code.tool` → `claude_code.tool.execution`).
Correlation keys: `session.id`, `prompt.id`, `tool_use_id`, and `event.sequence`
for ordering.

Content is gated and off by default: `OTEL_LOG_TOOL_DETAILS=1` for arguments,
`OTEL_LOG_TOOL_CONTENT=1` for output, `OTEL_LOG_RAW_API_BODIES=1` for full
request/response bodies (with `file:<dir>` for untruncated on-disk export).
Default content cap is 60 KB, tunable via
`CLAUDE_CODE_OTEL_CONTENT_MAX_LENGTH`.

**Hooks and OTel overlap, and we want both.** Hooks are synchronous, authoritative
for decisions, and available at events OTel has no equivalent for
(`InstructionsLoaded`, `ConfigChange`). OTel is richer on content, carries the
span hierarchy, and — critically — **can be locked to a destination in managed
settings, with developer-set variables removed to prevent redirection.** Use hooks
for control and structure, OTel for content and for a tamper-resistant second
copy of the stream.

### MCP interposer — the metadata point

Hooks see tool *calls* (`tool_name`, `tool_input`). They do not see the tool
*descriptions and schemas* the server advertised, which is exactly the tool-
poisoning vector, and they cannot tell that a server's advertised surface changed
between approval and use.

`mcp-interpose` is configured as the server command in `.mcp.json`, wrapping the
real server. It sees `tools/list` responses (descriptions, schemas, annotations),
call arguments, and results. Its jobs:

1. Hash every tool's name, description, and input schema. Compare against the
   approved baseline on each session. Any delta is a rug-pull candidate.
2. Scan description and schema text for instruction-shaped language, and for
   references to tools or servers other than its own (the shadowing signature).
3. Record results as provenance ingest with the server's trust label.
4. Carry MCP tool annotations (`readOnlyHint`, `destructiveHint`,
   `idempotentHint`, `openWorldHint`) into the event stream as *inputs to policy*
   — never as authority. The MCP spec states these are hints and that clients
   should not trust them when the server itself is untrusted. We use
   `openWorldHint` to classify a result as untrusted ingest and `destructiveHint`
   to raise required approval, but a server claiming `readOnlyHint: true` earns no
   relaxation. Asymmetric trust: hints can only make policy stricter.

### Managed settings — the anchor

Everything above is configuration, and configuration on a compromised endpoint is
attacker-editable. Managed settings (MDM-delivered file, or server-managed
settings on claude.ai) sit at the highest precedence: **no other level, including
command-line arguments, overrides a managed permission rule**, and managed hooks
cannot be disabled by user or project settings.

The managed bundle carries:

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
and honors only managed-settings entries. `failIfUnavailable` refuses to start
rather than silently running unsandboxed. `disableBypassPermissionsMode` is the
direct counter to the s1ngularity invocation pattern.

## Trust boundaries

| Boundary | Direction | Control |
| --- | --- | --- |
| MCP server → interposer | inbound, untrusted | Metadata hashing, description scanning, results labelled untrusted |
| Claude Code → agentd | inbound, semi-trusted | Structurally cannot widen permissions (deny-first precedence) |
| agentd → fleet ingest | outbound, one-way | Write-only endpoint; redacted at source; not reachable from sandboxed agent subprocesses |
| fleet → agentd | inbound policy | Signed policy bundles, version-pinned; `agentd` refuses unsigned or downgraded bundles |
| Developer/malware → settings | adversarial | Managed settings outrank all; `ConfigChange` and `FileChanged` report attempts |

## Why a local daemon rather than hooks calling the fleet plane directly

`PreToolUse` is synchronous on **every** tool call. A round trip to a central
service puts fleet-wide network latency and availability in the critical path of
every file read on every developer's machine. When the central service is slow or
down you must choose between failing open (the gate silently stops existing) and
failing closed (every developer on the fleet stops working simultaneously).
Neither is acceptable as a steady state.

`agentd` decides locally from a cached signed policy bundle, targets single-digit
milliseconds, and streams to the fleet asynchronously. The fleet plane's
availability then affects detection latency, not developer throughput.

## Latency budget and failure modes

| Path | Budget | On timeout |
| --- | --- | --- |
| `PreToolUse` → decision | p99 ≤ 5 ms, hard ceiling 250 ms | See fail policy below |
| `PostToolUse` ingest | fire-and-forget, never blocks | Drop to local spool |
| Async detectors (goal drift) | seconds | Advisory only; never gates inline |
| Fleet push | minutes | Local spool, bounded on disk, oldest-dropped with a gap marker |

**Fail policy on `agentd` unavailability.** Split by action class, not global:

- **Fail closed** for a small, explicitly enumerated set of high-impact classes:
  writes to credential paths, outbound network from Bash, `git push`, MCP tools
  annotated destructive, writes outside the working directory.
- **Fail open** for everything else, and **emit a fail-open record on every
  occurrence**. A run of fail-opens is itself an alert — it is what suppressing
  the daemon looks like.

The rationale for not failing closed globally: a bug in `agentd` would otherwise
halt every developer at once, which guarantees the system gets disabled. A
narrow fail-closed set keeps the catastrophic actions gated while keeping the
blast radius of our own outage survivable.

## Tamper resistance, honestly

`agentd` runs as the user on a machine adversary A1 fully controls. It can be
killed. The mitigations are not "make it unkillable" — they are:

1. **Policy delivered above the attacker's reach.** Managed settings cannot be
   overridden by CLI args, project settings, or user settings. The sandbox, the
   egress allowlist, and `disableBypassPermissionsMode` hold even with `agentd`
   dead.
2. **Silence is a signal.** The fleet plane knows the enrolled endpoint roster and
   expects a continuous heartbeat plus a session stream. A quiet endpoint that is
   still checked into work, or a session that reaches the fleet via OTel with no
   corresponding hook stream, is an alert. Suppressing the daemon is therefore
   detectable even though it is not preventable.
3. **Two independent paths.** Hooks (localhost, killable with the daemon) and OTel
   (destination pinned in managed settings). Losing one while the other continues
   is a high-signal discrepancy.

Residual risk is real and stated in [01](01-threat-model.md): this makes endpoint
compromise visible and expensive, not impossible.
