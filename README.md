# ambit

A provenance and control plane for Claude Code agents and the MCP servers they
connect to, with **Wazuh as the fleet plane** and support for third-party security
firms monitoring the deployment.

## The problem

A company runs many coding-agent instances. Each one holds a developer's filesystem
access, credentials, and network reach. Each one continuously ingests untrusted
content — web pages, issue bodies, dependency source, MCP tool results, CI logs. Any
of that content can carry instructions.

The documented attacks are not hypothetical:

- **s1ngularity** (August 2025): malicious `nx` npm versions shipped a
  `telemetry.js` post-install script that looked for locally installed AI CLI agents
  (Claude, Gemini, Amazon Q) and re-invoked them with permission-bypass flags
  (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) to inventory and
  exfiltrate SSH keys, `.env` files, and cloud credentials to attacker-visible public
  GitHub repos. Malware using the developer's own agent as its recon tool.
- **GTG-1002** (disclosed 13 November 2025): a state-linked actor decomposed an
  espionage campaign into thousands of individually innocuous subtasks and framed the
  session as authorized penetration testing, getting Claude Code to execute an
  estimated 80–90% of the intrusion across ~30 targets with humans at only 4–6
  decision points.
- **MCP supply chain**: tool poisoning (adversarial text in tool descriptions and
  schemas), rug pulls (a server approved benign, updated malicious), and cross-server
  shadowing (one server's description altering behavior toward another's tools).

The unifying shape: **the agent's actions stop serving the task it was given, and each
individual action still looks legitimate.** The research consensus is that
reasoning-level monitoring is a weakening signal and *action*-level monitoring is the
durable one.

## What this is

Two layers, deliberately split by latency.

**`ambitd` on each endpoint** holds everything needing live session state or an inline
verdict — because `PreToolUse` needs an answer in single-digit milliseconds and no SIEM
can provide one:

- Rule-of-Two bit accounting (untrusted input / sensitive data / external
  communication)
- The provenance fingerprint intersection
- **The gate** — `allow` / `deny` / `ask`
- Async goal-drift scoring against the objective the user actually stated

**Wazuh as the fleet plane** holds everything that is cross-event or cross-endpoint
correlation, and it absorbs a large amount of what would otherwise have been our
software: event store, retention, alerting, the review queue, enrollment, and
heartbeat. Agent-disconnect alerting gives detector D7 natively (rule 504, already
tagged MITRE T1562.001). FIM with `whodata` on `.claude/` and `.mcp.json` covers most
of D6. SCA policy files assert the managed-settings bundle is present and correct
(D12). Every alert carries ATT&CK technique IDs.

**Events reach Wazuh already carrying the verdict and the provenance edge.** Wazuh is
not in the synchronous path and never blocks a tool call. Active response is
containment only — credential revocation on a high-confidence detector — never a gate.

Transport is deliberately boring: `ambitd` writes JSON lines to a local file, the Wazuh
agent tails it with `log_format json`, and there is no custom decoder. Detectors become
custom rules at ID ≥ 100000, each with a runbook.

## Why this exists at all

Claude Code already ships a strong *preventive* layer: an OS-enforced Bash sandbox with
filesystem and network isolation, an egress allowlist with managed lockdown, credential
masking with proxy-side injection, deny rules that managed settings pin above every
other scope, and 33 hook events that can block a tool call before it runs. See
[docs/06-prior-art.md](docs/06-prior-art.md).

What does not exist, and is therefore what this repo designs:

1. **Provenance.** Nothing links "this agent ingested untrusted content" to "this agent
   then took this action."
2. **Rule-of-Two accounting at runtime.** The three properties are observable from the
   hook stream; nothing tracks them per session or gates on the third.
3. **Goal-drift detection.** Nothing scores an action against the objective the user
   stated — the covert-side-task signal.
4. **MCP change detection.** Nothing notices that a server's tool descriptions changed
   between the review that approved it and the call that trusts it.
5. **Managed-settings verification.** The anchor everything rests on was previously
   assumed; SCA makes it checked.

The system is a **consumer and configurator of Claude Code's primitives and Wazuh's
platform, not a replacement for either.**

## Documents

| Doc | Contents |
| --- | --- |
| [00-sources.md](docs/00-sources.md) | Every claim with primary / secondary / unverified status |
| [01-threat-model.md](docs/01-threat-model.md) | Five adversaries, assets, trust assumptions, the MSSP egress posture, residual risk |
| [02-architecture.md](docs/02-architecture.md) | `ambitd`, `mcp-interpose`, Wazuh; interception points; FIM and SCA config; trust boundaries; latency and failure modes |
| [03-detection.md](docs/03-detection.md) | Three detection layers, the ambitd/Wazuh split, rule snippets, D1–D12, ATT&CK mappings, runbook requirements |
| [04-data-model.md](docs/04-data-model.md) | Rich internal schema, flattened SIEM-bound schema, the mapping and what it loses, what crosses to Wazuh, split retention |
| [05-build-plan.md](docs/05-build-plan.md) | M0–M5, what adopting Wazuh deletes, enforcement sequenced after a measured baseline |
| [06-prior-art.md](docs/06-prior-art.md) | What already exists, reuse decisions, ten non-goals |
| [07-open-questions.md](docs/07-open-questions.md) | Thirteen decisions, four resolved; Q11 (tenancy) blocks MSSP onboarding |
| [08-mcp-interpose-decision.md](docs/08-mcp-interpose-decision.md) | Q2 resolved: why `mcp-interpose` is purpose-built rather than adopted, with the evaluation evidence |
| [09-adrian-evaluation.md](docs/09-adrian-evaluation.md) | Q13 resolved: why Adrian doesn't cover M1/M2, and the one finding that changes how the comparison reads |
| [10-wazuh5-migration.md](docs/10-wazuh5-migration.md) | Q12 resolved: 5.0's rule engine has no home for `frequency`/`same_field`/`if_matched_sid`, evaluated against the actual 5.0.0-beta5 source |

## Third-party monitoring

An external firm reads the Wazuh copy: the digest-bearing event and alert stream. They
do not receive the trajectory spool, content blobs, path-digest reverse maps, or the
HMAC key, and they hold no active-response dispatch permission.

**Zone labels (`credential`, `workdir`, `untrusted`, `system`, `home`) are in
cleartext; paths are keyed digests.** That is what makes an alert triageable without
handing over a map of our source tree. Digest resolution runs on our side on request,
and **every runbook must be written for an analyst who cannot see our source tree.**

These are policy controls resting on Wazuh RBAC, agent groups, and index-level
restrictions — and Wazuh's multi-tenancy is thin. Until
[Q11](docs/07-open-questions.md) is settled they are intentions, not enforced
guarantees, and the docs say so rather than claiming coverage.

## Code

M0 is implemented: `ambitd` is **observe-only**. It receives Claude Code hook
events, normalizes them, writes the full trajectory to a local spool and the
filtered security-relevant slice to a file the Wazuh agent tails. It returns no
decision, so no session behaves differently for its presence — that is the
milestone guarantee, because a baseline cannot be measured from a system that is
already changing behavior.

```
cmd/ambitd/              the endpoint daemon
cmd/mcp-interpose/       the MCP interposer: one per server, in front of it
internal/event/          rich internal schema + flattened SIEM-bound schema
internal/classify/       path zone and bash command classification
internal/r2/             Rule-of-Two bit classification (shadow mode; see docs/07 Q1)
internal/features/       keyed fingerprint extraction
internal/redact/         secret detection and stripping at the edge
internal/filter/         what crosses to Wazuh
internal/hook/           Claude Code hook HTTP endpoint
internal/otlp/           OTLP/HTTP receiver (http/json, zero dependencies)
internal/mcp/            MCP stdio framing, tool metadata, the canonical hash
internal/toolscan/       D5: instruction-shaped metadata, cross-server references
internal/baseline/       D4: the approved baseline and its state machine
internal/interpose/      the passthrough, the analyzer, the loopback report
internal/loopback/       one definition of the loopback-bind control
internal/sink/           JSON-lines writer with rotation and gap markers
internal/collector/      wiring: payload -> event -> sinks
internal/config/         configuration, deliberately not delivered over Wazuh
deploy/wazuh/            localfile, syscheck, SCA policy, logtest fixtures
deploy/wazuh/rules/      all twelve detectors, six files, validated by go test
deploy/wazuh/runbooks/   one per detector, for an analyst with no access to our source
deploy/claude-code/      managed-settings bundle (M0: observation only)
```

```sh
./scripts/dev-local.sh          # run it against your own Claude Code sessions
./scripts/dev-local.sh --status  # the M0 interesting-fraction readout
make check   # go vet + race tests + gofmt
make build   # bin/ambitd, bin/mcp-interpose
make smoke   # end-to-end: inert responses, correct filtering, no leaks
make cross   # static binaries for darwin/linux, arm64/amd64
make fixtures # regenerate the Wazuh rule fixtures from the real pipeline
```

`mcp-interpose` goes in front of one MCP server, per server, so Claude Code still sees
that server under its own name and tool identity stays `mcp__<server>__<tool>`:

```jsonc
{
  "mcpServers": {
    "github": {
      "command": "mcp-interpose",
      "args": ["-server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

```sh
mcp-interpose -server github -show      # what the server has advertised so far
mcp-interpose -server github -approve   # the explicit operator step D4 compares against
mcp-interpose -server github -revoke    # withdraw approval after an incident
```

Three properties the tests enforce, each because getting it wrong is silent:

- **`ambitd` is inert.** Every hook response is `{}`. An empty response means no
  opinion, so Claude Code's permission pipeline behaves as if no hook were
  installed. Returning `allow` would *not* be equivalent — it suppresses the
  prompt a developer would otherwise see.
- **Nothing sensitive reaches the SIEM sink.** Paths are keyed HMAC digests with
  only the zone label in cleartext; secret values are stripped at the edge and
  only the kind is recorded; prompt text has no field in the flattened schema and
  stays in the spool.
- **The event stays narrow.** Wazuh drops events that exceed the JSON decoder's
  field limit, which is detection loss with no error at the detector. A test fails
  the build if a flattened event grows past its budget.
- **Interposing an MCP server is invisible.** Frames are forwarded before they are
  parsed, byte for byte, and the smoke test asserts the client's stream and exit code
  are identical to running the wrapped server directly. Every failure mode —
  unreachable daemon, unwritable baseline, hostile frame — degrades to plain
  passthrough and is reported rather than absorbed, because an interposer that can
  break a developer's tools would be removed from the fleet within a week, and because
  a silent detector that reports "no drift" when it compared nothing is worse than
  none.
- **A misconfigured second stream is loud, not silent.** The OTLP receiver speaks
  `http/json` only and answers 415 on protobuf, and `ambitd` reports `degraded`
  health when exports are rejected or when exactly one of the two collection paths
  goes silent. "Configured but never received" is the failure mode that would
  otherwise hide.

## Status

fraction** — are still open.

From M1, the **endpoint half is built**: `mcp-interpose` implements D4 (metadata
hashing against an approved baseline, with an explicit operator approval step) and D5
(instruction-shaped metadata and cross-server references), carries MCP annotations
stricter-only, and emits `mcp_list` events through `ambitd`. The **Wazuh half of M1 is also written**: rules for
all twelve detectors (IDs 100200–100319, six files) with a runbook each, validated offline
by `go test` against fixtures generated from the real pipeline rather than hand-written.

Three of those rules are inert and marked as such rather than shipped as if they worked —
`agent_entrypoint` has no emitter anywhere, MCP annotations do not reach tool-call events,
and the policy engine that sets `policy_decision` is M3. Sandbox allowlist denials have no
schema field at all. [03-detection.md](docs/03-detection.md) records all four.

What M1 still needs is the MCP inventory across a real cohort, confirmation on a live
manager of three things that fail silently (the syscheck and SCA parent SIDs, and how a
rule matches an array-valued field), and the exit criterion that actually tests a runbook:
someone outside the team executing one against a sample alert. Two limits are stated in
the code and in [02-architecture.md](docs/02-architecture.md) rather than implied: a
stdio wrapper does not cover MCP servers reached over HTTP/SSE, and `mcp_list` events
usually carry no session id because MCP does not carry one. M2 onward is design only,
with one exception: Q1's Rule-of-Two bit accounting (`internal/r2`) is built and
running in shadow mode ahead of M2 proper, specifically to start gathering the
saturation data that question needs — see
[07-open-questions.md](docs/07-open-questions.md) Q1. It computes and records bits
only; no gate, no alert, no change to session behavior.

Nothing here is final —
[07-open-questions.md](docs/07-open-questions.md) lists what still needs deciding, and
five of the thirteen are blocking. Q2 (build vs. adopt for the MCP interposer) is now
decided — [08-mcp-interpose-decision.md](docs/08-mcp-interpose-decision.md). Q13
(evaluate Adrian before M1) is decided —
[09-adrian-evaluation.md](docs/09-adrian-evaluation.md): build continues, the overlap
does not fit. Q12 (target Wazuh 4.x or 5.x) is decided —
[10-wazuh5-migration.md](docs/10-wazuh5-migration.md): stay on 4.x, since 5.0's rule
engine has no shipped mechanism for the correlation primitives D2, D10 and D11 depend
on.

## Sourcing note

Claude Code's hooks, permissions, sandboxing, telemetry, and managed settings were
verified against the official documentation at `code.claude.com`. Wazuh specifics —
rule syntax, JSON decoder constraints, FIM, SCA, agent-disconnect alerting, archiving
— were verified against the Wazuh 4.x documentation source and shipped ruleset, since
`documentation.wazuh.com` is unreachable from this environment; each claim's status is
recorded in [00-sources.md](docs/00-sources.md). Claims that rest on secondary sources
or post-May-2026 publications are marked *(unverified)* where they appear.
