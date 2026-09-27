# 08 — Q2 decided: build `mcp-interpose`, adopt neither gateway

[07](07-open-questions.md) Q2 asked whether to write `mcp-interpose`, fork an
existing MCP gateway, or write a plugin for one, and said the question needed
"an owner and a decision, not a default." This is that decision, with the
evidence it rests on.

**Decision: write a minimal purpose-built interposer, in Go, in this repo. Adopt
neither candidate, and do not write a plugin for either.** Take two things from
them anyway — lasso's description-pattern corpus as a starting point for D5, and
enkrypt's deliberately-malicious test servers as M1 fixtures.

The short version: **neither gateway does the one thing that is our contribution**
(D4 — hashing tool metadata and diffing it against an approved baseline; neither
repo hashes tool metadata at all), and **both destroy a property M0 already
depends on** (the `mcp__<server>__<tool>` tool identity that
`internal/hook/payload.go:157` parses and that managed-settings permission rules
match). The cost of adopting is not neutral-to-positive as the question assumed;
it is negative before the first line of our own code.

## What was evaluated

| | lasso-security/mcp-gateway | enkryptai/secure-mcp-gateway |
| --- | --- | --- |
| Commit | `7e7f1f6`, 2026-01-22 | `b624edf`, 2026-09-24 |
| Version | 1.2.1 | 2.2.4 |
| License | MIT | Apache-2.0 |
| Language | Python ≥3.10 | Python ≥3.10 |
| Size | ~5.9k LOC | ~75k LOC |
| Direct deps | 3 (`mcp[cli]`, `beautifulsoup4`, `requests`) | 22 (flask, fastapi, uvicorn, redis, aiohttp, pydantic, cryptography, pyjwt, psutil, …) |
| Extension surface | `Plugin` ABC: guardrail + tracing types, `--plugin <name>` | provider plugins (guardrail / auth / telemetry / sandbox) loaded by dotted class path |
| External service | GitHub / npm / Smithery at scan time | `api.enkryptai.com` for guardrails, config, registry |

The other two names in [06](06-prior-art.md) — reaatech/mcp-gateway and Bifrost —
were not evaluated; Q2 named these two, and the conclusion below is
architectural rather than implementation-specific, so it is unlikely a third
gateway changes it. If one is proposed later, run it against the same eight
tests.

## The requirements, as tests

From [02](02-architecture.md)'s four jobs for `mcp-interpose`, plus the
operational constraints the rest of the design already commits to:

| | Requirement | Source |
| --- | --- | --- |
| R1 | Hash tool name + description + input schema; diff against an **approved baseline** across sessions (D4) | [02](02-architecture.md), [03](03-detection.md) |
| R2 | Scan description and schema text for instruction-shaped language and cross-server references (D5) | [02](02-architecture.md) |
| R3 | Record tool results as provenance ingest carrying the server's trust label | [02](02-architecture.md) |
| R4 | Carry MCP annotations into the event stream, **stricter-only**, never as authority | [02](02-architecture.md) |
| R5 | Preserve tool identity as Claude Code names it: `mcp__<server>__<tool>` | `internal/hook/payload.go:157`, `deploy/claude-code/managed-settings.m0.json` |
| R6 | No enforcement before M3, and no developer-visible behavior change at M0 | [05](05-build-plan.md) |
| R7 | No new language runtime and no new outbound dependency on the endpoint | `Makefile` (static binaries), managed-settings OTLP comment (zero-dependency daemon) |
| R8 | Emit in our flattened schema to the local sink | [04](04-data-model.md) |

R5, R6 and R7 are not preferences. R5 is load-bearing for code that is already
written and tested; R6 is the M0 exit criterion; R7 is the stated reason
`ambitd` has zero dependencies and ships as a static binary.

## Scorecard

| | lasso | enkrypt | build |
| --- | --- | --- | --- |
| R1 metadata hash + baseline | **No** — no hashing anywhere in the repo | **Hook yes, implementation no** | Yes |
| R2 description scan | Partial — regex corpus exists, not extensible, not at a plugin point | Via cloud guardrail call, or our own provider | Yes |
| R3 provenance ingest + trust label | Plugin sees results; no trust label concept | Plugin sees results; no trust label concept | Yes |
| R4 annotations carried | **No — actively destroyed** | Captured at discovery; reachable from a provider | Yes |
| R5 tool identity preserved | **No** — renames to `<server>_<tool>` under one gateway entry | **No** — collapses to a single `enkrypt_secure_call_tools` | Yes |
| R6 no enforcement before M3 | **No** — blocks servers by rewriting `.mcp.json`, fails closed on error | Configurable; enforcement is the default posture | Yes |
| R7 endpoint footprint | Python + 3 deps + outbound to GitHub/npm/Smithery | Python + web stack + outbound to `api.enkryptai.com` | No change |
| R8 our schema | Plugin would write it | Provider would write it | Native |

## lasso-security/mcp-gateway

**R1 fails outright.** A search for `sha256`, `hashlib`, `baseline`, `drift`,
`first-seen` and `approved` across the repository returns nothing. There is no
metadata hash, no persisted baseline, and therefore no rug-pull detection: the
scanner renders a fresh verdict from regexes at every startup. That is the
static-scanner shape [06](06-prior-art.md) lists as **non-goal 5**, not the
runtime baseline diffing we need.

**The plugin surface cannot host R1, R2 or R4.** `PluginContext`
(`mcp_gateway/plugins/base.py`) carries exactly `server_name`,
`capability_type`, `capability_name`, `arguments`, `response`, `mcp_context`. No
description, no `inputSchema`, no annotations — the metadata we exist to hash is
not in the object plugins receive. And `tools/list` never passes through the
plugin manager at all: `Server.list_tools` (`mcp_gateway/server.py:312`) returns
a cached list with no `plugin_manager` parameter and no `sanitize_*` call, while
every plugin invocation is on call arguments or call results
(`mcp_gateway/sanitizers.py`). The one place tool descriptions *are* examined —
`Scanner.scan_server_tools` — is hardcoded into gateway startup behind a
`--scan` flag (`mcp_gateway/gateway.py:268`), not a plugin point.

**R4 is not merely missing, it is destroyed.** `register_dynamic_tool`
(`mcp_gateway/gateway.py:37`) re-registers each proxied tool on its own FastMCP
instance from the name, the docstring, and the parameter signature. MCP
annotations — `readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint` — are not carried through. (The `annotations` dict in that
function is Python type annotations, an unrelated thing.) Adopting lasso would
mean the annotations `internal/event/flat.go:53-55` already has fields for, and
which [02](02-architecture.md) uses to classify untrusted ingest and to raise
required approval, stop reaching us.

**R6 fails, and fails in the direction that matters.** On a risky verdict the
scanner sets `blocked` and rewrites the user's MCP config file
(`Scanner.edit_mcp_config_file`), killing the server. Both scan paths block on
*error* too — `except Exception` → `blocked = "blocked"` → config rewritten.
That is enforcement, fail-closed, at the point in our plan where enforcement is
explicitly forbidden, and it is enforcement by mutating the very file our FIM
watch is pointed at: `deploy/wazuh/ossec-syscheck.xml` watches `.mcp.json` with
`whodata` for D6. An adopted lasso would generate D6 evidence as routine
operation, which is precisely how a detector gets tuned into uselessness.

**R7 adds an outbound dependency.** `Scanner.is_risky` scores a server's
reputation by looking up its npx package or Smithery slug against
`api.github.com`, `registry.npmjs.org`, `api.npmjs.org` and `smithery.ai`. That
is a startup-time network call from every endpoint, keyed on the names of the
MCP packages we run — a disclosure to three third parties of our internal tool
surface, in a design whose whole external-sharing posture is keyed digests and
cleartext zone labels only ([01](01-threat-model.md)). It also silently degrades
to "risky, blocked" on a restricted network.

## enkryptai/secure-mcp-gateway

This is the stronger candidate on the point that matters most, and the
evaluation should say so plainly.

**It has the right hook.** `GuardrailProvider` defines
`validate_tool_registration(ToolRegistrationRequest)` and
`validate_server_registration(...)`
(`src/secure_mcp_gateway/plugins/guardrails/base.py:327` and `:313`).
`ToolRegistrationRequest.tools` is a list of tool schemas, and the discovery
service captures `description`, `inputSchema` **and** `annotations` per tool
(`services/discovery/discovery_service.py:812-822`). The hook is called from
roughly a dozen sites in the discovery path, and providers are loaded by dotted
class path, so a custom provider is possible without forking. An ambit provider
implementing D4 and D5 there is a real option, not a hypothetical one. R1's
hook exists; only the implementation is missing, and the implementation is ours
either way.

**But the price of that hook is the whole gateway.** To reach it we take a
75k-LOC deployment onto every developer endpoint: flask *and* fastapi *and*
uvicorn, redis, aiohttp, cryptography, pyjwt, an OAuth implementation with PKCE
and token management, a session pool, a cache service with an optional external
KeyDB, a REST admin API with a 256-character `admin_apikey`, a config watcher,
and a 2,781-line discovery service. This is the exact failure mode Q2 named —
"a half-built gateway that needs auth, multi-tenancy, and transport handling we
did not plan for" — arriving fully built and needing to be operated. Every one
of those components is new attack surface and new patch burden inside the trust
boundary of the tool whose job is watching supply chains.

**Default operation sends tool content to a third party.** The shipped guardrail
provider POSTs text to `api.enkryptai.com/guardrails/guardrail/detect` and
siblings for relevancy, adherence, hallucination and PII
(`plugins/guardrails/enkrypt_provider.py:117, 322-325, 659, 857`), and in cloud
mode the gateway pulls the server list and policies from Enkrypt at request time
on a 5-minute TTL. Local-only operation is possible — local apikey auth, local
config, our own provider — so this is a configuration we could avoid rather than
a hard blocker. But it inverts the default: [04](04-data-model.md) keeps content
on the endpoint and ships digests, and Q3 is still open on how much content
leaves at all. Adopting a component whose out-of-the-box behavior is to POST
tool arguments and results to a vendor means the data-handling posture is now one
config key away from being violated, on every endpoint, forever.

## The blocker both share: tool identity

Both gateways aggregate. The client is configured with **one** MCP server entry
— the gateway — and the real servers are nested behind it. What Claude Code sees
downstream is not the real tool:

- **lasso** registers each proxied tool as `f"{server_name}_{tool.name}"`
  (`mcp_gateway/gateway.py:45`), so `filesystem`'s `read_file` arrives as
  `mcp__mcp-gateway__filesystem_read_file`.
- **enkrypt** exposes a fixed set of gateway tools and routes *every* downstream
  call through one of them, `enkrypt_secure_call_tools`
  (`src/secure_mcp_gateway/gateway.py:590`), with the real server and tool
  buried in the arguments. Every MCP action on the endpoint becomes one tool
  name.

Three consequences, all concrete:

1. **Already-written code mis-parses.** `IsMCPTool`
   (`internal/hook/payload.go:157`) splits `mcp__<server>__<tool>`. Under lasso
   every event reports `server = "mcp-gateway"`; under enkrypt every event
   reports `tool = "enkrypt_secure_call_tools"`. `tool_mcp_server` and
   `tool_mcp_tool` in the flattened schema stop being the fields
   [03](03-detection.md)'s rules correlate on. Per-server detection dies at the
   decoder.
2. **The managed-settings anchor loses its grip.** Permission rules match tool
   names. A `deny` on one MCP tool, pinned at the precedence level nothing
   overrides, is expressible today; behind either gateway there is one tool name
   to allow or deny, so the granularity our M3 enforcement ladder assumes is
   gone. The same applies to hook matchers.
3. **It contradicts the project's stance.** ambit is "a consumer and configurator
   of Claude Code's primitives, not a replacement for either." A component that
   makes Claude Code's own permission model coarser to install our telemetry is
   the wrong side of that line.

A per-server wrapper — `mcp-interpose` as the server command for each real
server, which is what [02](02-architecture.md) already specifies — has none of
these problems, because Claude Code still sees one MCP server per real server
under its real name.

## Why not a plugin, then

Q2's recommendation was "a plugin is the right shape if either has a plugin
surface." Both have one; the shape is still wrong, for reasons the plugin
surface cannot fix:

- A plugin cannot un-aggregate the gateway. R5 is broken by the host's
  architecture, not by a gap in its extension points.
- In lasso, the metadata a plugin would hash is not in `PluginContext` and
  `tools/list` never reaches a plugin, so the plugin would have to reach into
  `proxied_server._tools` — a private attribute — making us a fork in practice
  while pretending to be a plugin.
- In enkrypt, the provider we would write is a `GuardrailProvider` — a class
  whose declared job is to return allow/block verdicts — carrying our D4/D5
  logic as a side effect. We would be shipping enforcement machinery and then
  configuring it off until M3.
- Either way we write the hashing, the baseline store, the approval step, the
  scan, the trust labelling and the schema emission. That is ~90% of the work,
  and the remaining 10% — a stdio passthrough — is the part a gateway would give
  us, in exchange for a Python runtime, a web stack, and a broken tool name.

## What we build instead

`cmd/mcp-interpose`, a Go binary in this repo, configured per server in
`.mcp.json` as [02](02-architecture.md) describes. It is a stdio JSON-RPC
passthrough that parses the frames it forwards and emits events; it makes no
decisions before M3.

Most of what it needs already exists and is tested:

| Need | Already in repo |
| --- | --- |
| `mcp_list` event kind | `internal/event/event.go:30` |
| MCP block with trust label and metadata hash | `internal/event/event.go:144`, `internal/event/flat.go:50-56` |
| Annotations as pointers — absent ≠ false | `internal/event/event.go:154` |
| Keyed digests for fingerprints | `internal/features` (`Extractor.Digest`) |
| JSON-lines sink with rotation and gap markers | `internal/sink` |
| Edge redaction | `internal/redact` |
| Field-count budget enforced by test | `internal/event/flat_test.go` |

The genuinely new code is: stdio framing and passthrough, the `tools/list`
metadata hash, the baseline store with an explicit operator approval step, and
the D5 text scan. That is a small, bounded program — and it is the program Q2
called "our unique need is narrow."

**What it must not become**, restated so nobody adds it by accident: not an
auth layer, not multi-tenant, not a rate limiter, not an aggregator, not a
content guardrail, not a remote-transport proxy. It wraps one server, watches
what that server advertises, and emits. If it grows a config file with an API
key in it, something has gone wrong.

## What we take from them anyway

1. **lasso's pattern corpus as a D5 starting point.** `ToolAnalyzer`
   (`mcp_gateway/security_scanner/tool_poisoning_analyzer.py`) sorts description
   patterns into three categories — hidden instructions, sensitive file
   references, sensitive actions — which is a better decomposition than a single
   "looks like an instruction" regex, and it scans parameter descriptions as well
   as the tool description, which is a real vector we should cover. MIT-licensed;
   reimplement the categories in Go with attribution, and treat the specific
   regexes as a first draft to be measured, not adopted.
2. **enkrypt's `bad_mcps/` as M1 test fixtures.** Sixteen MCP servers,
   Apache-2.0 — fourteen deliberately malicious plus two benign echo servers
   for harness testing — including `tool_poisoning_mcp.py`
   (hidden instructions in descriptions), `schema_poisoning_mcp.py`, and
   `mpma_mcp.py` (preference-manipulation attacks that bias tool selection).
   M1's exit criterion is "a deliberately mutated test server triggers D4 within
   one session" — this is that test server, already written, with citations to
   the literature. A mutation harness on top gives D4's baseline-diff case,
   which none of the fixtures cover because none of the gateways do D4.

Both are additive and neither puts a dependency on the endpoint.

## Risks we accept

- **We own MCP transport edge cases.** Stdio framing, the `initialize`
  handshake, `notifications/tools/list_changed` (a server may re-advertise
  mid-session, which is a rug pull arriving as a notification rather than at
  startup — the interposer must hash on that path too, not only at first
  `tools/list`), and servers Claude Code reaches over HTTP/SSE rather than
  stdio, which a per-server stdio wrapper does not cover. The HTTP/SSE case
  needs a decision before M1 ships; if the cohort uses such a server, D4
  coverage for it is a gap and the docs must say so rather than implying
  coverage.
- **No community maintenance.** Nobody else patches our interposer. Bounded by
  keeping it small.
- **We will reimplement things gateways do better**, if scope creeps. Mitigated
  by the "must not become" list above and by non-goals 1-3 and 5 in
  [06](06-prior-art.md).

## What would reverse this

Any one of these, and Q2 is worth reopening:

- A gateway that proxies **per server, preserving `mcp__<server>__<tool>`**, with
  a hook at `tools/list` that carries description, schema and annotations.
- A gateway with a **native metadata baseline** — first-seen hash, operator
  approval, drift alert — so R1 is adoption rather than implementation.
- The cohort turns out to depend on **HTTP/SSE MCP servers** a stdio wrapper
  cannot wrap, making a proxy the only viable shape. This is the most likely
  reversal, and it is an empirical question M0 answers: the M0 stream records
  which MCP servers the cohort actually uses.
- Our interposer passes ~1.5k LOC without being feature-complete. That is the
  signal that "narrow" was wrong.

## Reproducing this evaluation

```sh
git clone --depth 20 https://github.com/lasso-security/mcp-gateway        # 7e7f1f6
git clone --depth 20 https://github.com/enkryptai/secure-mcp-gateway      # b624edf

# R1: neither repo hashes tool metadata.
grep -rn -i "sha256\|hashlib\|baseline\|drift\|first.seen" --include='*.py' mcp-gateway/
grep -rn -i "sha256\|hashlib\|baseline\|drift" --include='*.py' secure-mcp-gateway/src/
# lasso: no hits. enkrypt: cache keys, PKCE, OAuth, registry apikey — no tool metadata.

# lasso R5/R4: the rename, and annotations dropped on re-registration.
sed -n '37,46p;120,130p' mcp-gateway/mcp_gateway/gateway.py
# lasso: tools/list bypasses plugins entirely.
sed -n '312,315p' mcp-gateway/mcp_gateway/server.py

# enkrypt R1 hook and the metadata it carries.
sed -n '84,108p;325,340p' secure-mcp-gateway/src/secure_mcp_gateway/plugins/guardrails/base.py
sed -n '805,825p' secure-mcp-gateway/src/secure_mcp_gateway/services/discovery/discovery_service.py
# enkrypt R5: one tool for every downstream call.
grep -n "async def enkrypt_" secure-mcp-gateway/src/secure_mcp_gateway/gateway.py
```
