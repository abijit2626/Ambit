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
other scope, and 33 hook events that can block a tool call before it runs.

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

## Documentation

| Doc | Contents |
| --- | --- |
| [01-threat-model.md](docs/01-threat-model.md) | Five adversaries, assets, trust assumptions, the MSSP egress posture, residual risk |
| [02-architecture.md](docs/02-architecture.md) | `ambitd`, `mcp-interpose`, Wazuh; interception points; FIM and SCA config; trust boundaries; latency and failure modes; tenancy |
| [03-detection.md](docs/03-detection.md) | Three detection layers, the ambitd/Wazuh split, rule snippets, D1–D12, ATT&CK mappings, runbook requirements |
| [04-data-model.md](docs/04-data-model.md) | Rich internal schema, flattened SIEM-bound schema, the mapping and what it loses, what crosses to Wazuh, split retention |
| [05-mcp-interpose-decision.md](docs/05-mcp-interpose-decision.md) | Why `mcp-interpose` is purpose-built rather than adopted, with the evaluation evidence |
| [deploy/wazuh/README.md](deploy/wazuh/README.md) | Wazuh rules, SCA policy, FIM and localfile config, install and verification steps |
| [deploy/wazuh/runbooks/](deploy/wazuh/runbooks/) | One runbook per detector, written for an analyst with no access to our source |

## Third-party monitoring

An external firm reads the Wazuh copy: the digest-bearing event and alert stream. They
do not receive the trajectory spool, content blobs, path-digest reverse maps, or the
HMAC key, and they hold no active-response dispatch permission.

**Zone labels (`credential`, `workdir`, `untrusted`, `system`, `home`) are in
cleartext; paths are keyed digests.** That is what makes an alert triageable without
handing over a map of our source tree. Digest resolution runs on our side on request,
and **every runbook must be written for an analyst who cannot see our source tree.**

These are policy controls resting on Wazuh RBAC, agent groups, and index-level
restrictions — and Wazuh's multi-tenancy is thin. Until the
[tenancy model](docs/02-architecture.md#tenancy-for-third-party-monitoring) is settled
they are intentions, not enforced guarantees, and the docs say so rather than
claiming coverage.

## Code

`ambitd` is **observe-only** (M0; see the Roadmap below). It receives Claude Code hook
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
internal/r2/             Rule-of-Two bit classification (shadow mode; see docs/03-detection.md)
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
internal/fsperm/         private directories: 0700 on Unix, an explicit ACL on Windows
deploy/wazuh/            localfile, syscheck, SCA policy (Unix and Windows), logtest fixtures
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
make cross   # static binaries for darwin, linux and windows, arm64/amd64
make fixtures # regenerate the Wazuh rule fixtures from the real pipeline
```

### Windows

`ambitd` and `mcp-interpose` run natively on Windows (10, 11, Server), and in WSL2, where
they behave exactly as on Linux. The setup scripts have PowerShell counterparts that run
under both the Windows PowerShell 5.1 that ships with the OS and PowerShell 7:

```powershell
go build -o bin\ambitd.exe .\cmd\ambitd            # Go 1.24 or newer
powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1            # install
powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1 -Status    # the M0 readout
powershell -ExecutionPolicy Bypass -File .\scripts\dev-local.ps1 -Uninstall
powershell -ExecutionPolicy Bypass -File .\scripts\smoke.ps1                # end-to-end check
```

What differs from Unix, and why it matters:

- **There is no OS sandbox on native Windows.** Claude Code's sandbox runs on macOS, Linux
  and WSL2 only; on native Windows it runs commands unsandboxed
  ([sandboxing](https://code.claude.com/docs/en/sandboxing)). Detection is therefore the
  only layer there, and the detectors that read sandbox denials (D9's allowlist half) have
  no source. If you need the preventive layer, run Claude Code and `ambitd` inside WSL2.
  `deploy/wazuh/sca/ambit_managed_settings_windows.yml` leaves out the two checks that
  assert sandbox settings, because no configuration could satisfy them.
- **Privacy is an ACL, not a mode.** `0700` means nothing on Windows, and `%ProgramData%`
  is readable by every local user. Every directory `ambitd` creates, parents included, gets
  an explicit ACL (the account that created it, SYSTEM, Administrators), set with
  `icacls`; the Wazuh agent runs as SYSTEM and needs to read `events.jsonl`. If setting the
  ACL fails, what was created is removed again, so a later run cannot mistake it for
  somebody else's. A directory that already exists is never changed, but it is checked: one
  that `Users`, `Everyone` or `Authenticated Users` can read, or that an account other than
  the current user, SYSTEM or Administrators owns, is refused, and the error carries the
  `icacls` command that fixes it. That matters for an installer that pre-creates
  `%ProgramData%\ambit` to drop `config.json` into: restrict it first. Default data path:
  `%ProgramData%\ambit`. `mcp-interpose` runs as the developer, so its baselines default to
  `%USERPROFILE%\.ambit\baselines`, which the FIM configuration also watches.
- **Paths are normalized before anything is compared.** Windows drive paths are
  case-insensitive; Claude Code can report them with backslashes, as `/mnt/c/...` from WSL,
  or as `/c/...` from Git Bash. All of them reach the same zone label. Claude Code's
  `PowerShell` tool carries its script in `tool_input.command`, like `Bash`, and goes
  through the same classifier, which knows the common cmdlets, their aliases and
  `.exe`/`.cmd` suffixes.
- **Managed settings** live at `C:\Program Files\ClaudeCode\managed-settings.json`, or in
  `HKLM\SOFTWARE\Policies\ClaudeCode`. Claude Code does not read the legacy
  `C:\ProgramData\ClaudeCode`. The SCA policy reads the file, so an endpoint managed only
  through the registry would report check 10001 as failed.
- Wazuh agent configuration for Windows is in `deploy/wazuh/*.windows.xml`; see
  [deploy/wazuh/README.md](deploy/wazuh/README.md) for what is and is not verified.

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

Properties the tests enforce, each because getting it wrong is silent:

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

## Roadmap

Observe before enforce. A `PreToolUse` deny sits in the critical path of every tool
call on every endpoint, and a false deny stops a developer mid-task, fleet-wide and
simultaneously. So M0 and M1 cannot block; enforcement begins at M3 at `ask` rather
than `deny`, and each rule is promoted shadow → `ask` → `deny` on reviewed evidence
(at least two weeks at `ask`).

| Milestone | Scope | State |
| --- | --- | --- |
| **M0 Observe** | `ambitd` hook endpoint and OTLP receiver, spool and Wazuh sink, edge redaction, keyed features, FIM and SCA artifacts. Every hook response is `{}`. | Implemented and tested. Not yet deployed to a cohort. |
| **M1 Inventory, drift, first rules** | `mcp-interpose` (D4 baseline, D5 metadata scan), Wazuh rules for D1–D12 with runbooks, SCA policy. | Implemented. Rules validated offline against fixtures generated from the real pipeline; live-manager confirmation and an outside-analyst runbook test are open. |
| **M2 Provenance and Rule-of-Two, alert only** | Provenance engine, shadow-mode gates, replay harness. | Partial. Rule-of-Two bit accounting runs in shadow mode (`internal/r2`): it records bits, with no gate, no alert and no change to session behavior. The provenance engine, shadow verdicts and replay harness are not built. |
| **M3 Enforce** | Policy engine, signed policy bundles, split fail policy, containment-only active response. | Design only. |
| **M4 Goal drift** | Async scoring of actions against the stated objective. | Design only. |
| **M5 Fleet correlation** | Cross-session fingerprint set intersection; session-shape analysis. | Design only. |

Exit criteria gate each milestone. **M0:** a 5–10 endpoint volunteer cohort; p99 hook
response under 5 ms; zero developer-visible behavior change, verified by asking; local
spool event loss under 0.1%; the share of tool calls that cross to Wazuh measured
(design estimate 2–5%; `./scripts/dev-local.sh --status` reports it); and no
`Too many fields for JSON decoder` errors in the manager log. **M1:** every MCP server
the cohort uses inventoried with an approved baseline; a deliberately mutated server
triggers D4 within a session; killing `ambitd` fires D7 and stopping the Wazuh agent
fires rule 504; reverting a managed-settings key fires D12; and someone outside the
team executes a runbook against a sample alert.

## Known limitations

- **Wazuh 4.x only.** Wazuh 5.x has no mechanism for the `frequency`, `timeframe`,
  `same_*` and `if_matched_sid` primitives that D2, D10's tripwire and D11 depend on,
  and validates rule fields against a closed schema. See
  [deploy/wazuh/README.md](deploy/wazuh/README.md).
- **Third-party monitoring restrictions are intentions until a tenancy model is chosen
  and tested.** They rest on Wazuh RBAC, agent groups and index restrictions. See
  [docs/02-architecture.md](docs/02-architecture.md#tenancy-for-third-party-monitoring).
- **Three rules are inert and marked as such**, rather than shipped as if they worked:
  `agent_entrypoint` has no emitter, MCP annotations do not reach tool-call events, and
  the policy engine that sets `policy_decision` is M3. Sandbox allowlist denials have no
  schema field at all. [docs/03-detection.md](docs/03-detection.md) records all four.
- **Three Wazuh behaviors are unconfirmed on a live manager and fail silently when
  wrong:** the syscheck parent SIDs, the SCA parent SID, and how a `<field>` regex
  matches an array-valued field. Confirm them on the deployed version before relying on
  the rules that use them.
- **MCP coverage is stdio only.** `mcp-interpose` is a stdio wrapper and does not cover
  servers reached over HTTP/SSE. `mcp_list` events usually carry no session id, because
  MCP does not carry one.
- **Native Windows has no OS sandbox.** Claude Code's sandbox runs on macOS, Linux and
  WSL2; on native Windows it runs commands unsandboxed, so detection is the only layer
  there and the detectors that read sandbox denials have no source. The Windows SCA
  policy omits the two sandbox checks because no configuration could satisfy them. Run
  inside WSL2 to get the sandbox. See [Windows](#windows).
- **Wazuh behavior on a Windows agent is unconfirmed.** FIM wildcard expansion, log
  rotation under `log_format json`, SCA `f:` and `c:` rules and `whodata` have not been
  tried on a live agent, and each fails silently when wrong. See
  [deploy/wazuh/README.md](deploy/wazuh/README.md#windows-agents).
- **Rule-of-Two session scoping is unresolved.** Bits are monotonic per session. A
  session that runs long saturates to all three, and `/clear` is reported to start a new
  session id, which would reset bits B and C that should not reset. Shadow mode exists
  to measure both. See [docs/03-detection.md](docs/03-detection.md).
- **The goal-drift pre-filter must key on an action's own Rule-of-Two bits**, never on a
  session-level transition, or it skips every repeat of an already-tripped bit.
  Operator `TrustedMCPServers` classification is the larger coverage risk: marking a
  same-vendor admin tool `internal` removes it from Rule-of-Two and goal-drift coverage.

## Non-goals

Out of scope, so nobody builds them by accident:

1. **A sandbox.** Claude Code's is OS-enforced and better than anything written here.
2. **An egress proxy or allowlist engine.** Claude Code has one, with managed lockdown.
3. **A credential vault or masking layer.** Claude Code has one.
4. **A prompt-injection classifier as the primary defense.** Architecture and
   blast-radius reduction over filtering; a classifier may be one weak signal, never the
   boundary.
5. **A static MCP scanner.** Runtime baseline diffing is a different thing.
6. **An eval harness.** AgentDojo, SHADE-Arena and ControlArena are the regression suite.
7. **Model-level alignment or sabotage evaluation.** This monitors deployed agents under
   the assumption that the model is hijacked, not scheming.
8. **Blocking on reasoning content.** Chain-of-thought monitoring is the fragile signal;
   actions are monitored instead.
9. **SIEM functionality.** Wazuh is the event store, retention engine, alert router and
   review queue. The one exception is the local spool, which exists because the full
   trajectory must not go to the indexer.
10. **A custom Wazuh decoder.** The built-in JSON decoder gives addressable fields from
    `log_format json`; the flattened schema exists so that it suffices.

## Verification

Claude Code's hooks, permissions, sandboxing, telemetry and managed settings were
checked against the official documentation at `code.claude.com`. Wazuh specifics — rule
syntax, JSON decoder constraints, FIM, SCA, agent-disconnect alerting — were checked
against the Wazuh 4.x documentation source and shipped ruleset. Anything not confirmed
is marked *unverified* in the rules, runbooks and docs where it matters.

The Go packages, both PowerShell scripts and the interposer's end-to-end behavior are
exercised on a real Windows host by the `windows` job in
`.github/workflows/check.yml`, under Windows PowerShell 5.1 and PowerShell 7. That covers
`ambitd`, `mcp-interpose` and the installer; it does not cover a Wazuh agent on Windows,
and Claude Code's own hook payloads on Windows were read from its documentation rather
than captured.
