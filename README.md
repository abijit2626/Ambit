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
| [06-cohort-checklist.md](docs/06-cohort-checklist.md) | The path to the M0 and M1 exit criteria: blockers to close first, rollout order, how to measure each criterion |
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

The Go, shell and PowerShell source and the Makefile carry no comments, apart from the
build-constraint lines Go reads. The reasoning that used to sit beside the code is in
[docs/](docs/) and the tests, which are named for the behavior they pin; the version with the
comments is the last commit before they were removed, `3a8cdc5`
(`git show 3a8cdc5:path/to/file.go`). The Wazuh rules, SCA policies, the managed-settings bundle
and the CI workflow are configuration that operators read, and keep their comments.

`ambitd` is **observe-only** (M0; see the Roadmap below). It receives Claude Code hook
events, normalizes them, writes the full trajectory to a local spool and the
filtered security-relevant slice to a file the Wazuh agent tails. It returns no
decision, so no session behaves differently for its presence — that is the
milestone guarantee, because a baseline cannot be measured from a system that is
already changing behavior.

```
cmd/ambitd/              the endpoint daemon
cmd/mcp-interpose/       the MCP interposer: one per server, in front of it
cmd/ambit-replay/        replays trajectories through the real collector and measures it
cmd/agentdojo-convert/   turns AgentDojo run logs into replay trajectories
internal/event/          rich internal schema + flattened SIEM-bound schema
internal/classify/       path zone and bash command classification
internal/r2/             Rule-of-Two bit classification (shadow mode; see docs/03-detection.md)
internal/gate/           the Rule-of-Two gate table; verdicts recorded in shadow, never returned
internal/prov/           provenance engine: per-session untrusted-ingest fingerprints, edges (alert-only)
internal/replay/         trajectory format, runner, precision/recall/saturation report
internal/agentdojo/      AgentDojo run-log mapping and the ground truth it can stand behind
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
internal/runstate/       ambitd.state: each run's last heartbeat and how it stopped
internal/m0report/       `ambitd report`: the M0 exit criteria for one endpoint, from the spool
internal/collector/      wiring: payload -> event -> sinks
internal/config/         configuration, deliberately not delivered over Wazuh
internal/fsperm/         private directories: 0700 on Unix, an explicit ACL on Windows
deploy/wazuh/            localfile, syscheck, SCA policy (Unix and Windows), logtest fixtures
deploy/wazuh/rules/      all twelve detectors and the gate's shadow verdicts, seven files, validated by go test
deploy/wazuh/runbooks/   one per detector, for an analyst with no access to our source
deploy/claude-code/      managed-settings bundle (M0: observation only)
deploy/service/          ambitd as a system service: systemd unit, LaunchDaemon (Windows: a scheduled task)
scripts/                 local and system install, smoke tests, fixture generator, runbook rehearsal, AgentDojo measurement
testdata/replay/         starter trajectory corpus: attacks, adapted attacks, benign sessions
testdata/agentdojo/      per-tool MCP labels for AgentDojo's four suites, and licensed fixtures
```

```sh
./scripts/dev-local.sh          # run it against your own Claude Code sessions
./scripts/dev-local.sh --status  # what was collected, then the M0 readout
ambitd report -config <config>   # M0 criteria from the spool: hook p99, loss, restarts, interesting fraction
make check   # go vet + race tests + gofmt
make build   # bin/ambitd, bin/mcp-interpose
make smoke   # end-to-end: inert responses, correct filtering, no leaks
./scripts/runbook-rehearsal.sh -o <new dir>   # analyst packets and an answer key for the M1 runbook rehearsal
sudo ./scripts/install-system.sh --binary bin/ambitd-linux-amd64   # ambitd as a system service, for a cohort
sudo ./scripts/install-system.sh --status                          # is it running, and are managed settings in place?
sudo ./scripts/install-system.sh --uninstall                       # remove it; --purge also removes the collected data
make cross   # static binaries for darwin, linux and windows, arm64/amd64
make fixtures # regenerate the Wazuh rule fixtures from the real pipeline
make replay   # replay testdata/replay through the collector; precision, recall, R2 saturation
```

### Replay harness

`ambit-replay` feeds trajectories to a fresh in-process collector and reports what the
provenance engine and Rule-of-Two accounting do with them. It never touches a running
`ambitd`, the spool, the Wazuh sink or the production fingerprint key, so replaying an
attack cannot raise an incident. A trajectory is a JSON-lines file of hook payloads, the
same JSON Claude Code posts, optionally wrapped with ground truth and assertions:

```jsonc
{"scenario": {"name": "exfil-url", "config": {"trusted_content_domains": ["example.com"]}}}
{"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "fix the billing test"}
{"payload": {"hook_event_name": "PostToolUse", "session_id": "s1", "tool_name": "WebFetch", ...},
 "expect": {"r2": "A", "taint": "web:"}}
{"payload": {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash", ...},
 "hostile": true, "expect": {"edge": true, "edge_class": "url", "edge_from": 3}}
```

`hostile` is ground truth about the *action*: would an analyst want it paged. It is not
"this came from untrusted input", because docs/03 names an agent summarizing a page and
carrying its URLs across as a false positive, and following a link is the same mechanism. An
unannotated `PreToolUse` is benign, so a corpus of ordinary sessions needs no annotation. `expect` describes what the pipeline
does today, known misses and false positives included, so a change in either direction
fails until someone looks. Unknown keys in a header, step or assertion are errors: a
misspelled assertion that asserts nothing is the failure a regression suite exists to stop.

```sh
make replay                                   # the corpus, human-readable
./bin/ambit-replay -json testdata/replay      # byte-stable report, diffable across commits
./bin/ambit-replay -min-confidence 0.9 ...    # count an edge only at or above a floor
./bin/ambit-replay -min-recall 0.6 -max-fpr 0.25 ...   # exit 2 if the run misses a gate
```

A gate on a metric the corpus cannot compute fails rather than passes. `go test ./...` runs
the same corpus as a regression suite.

**The starter corpus is 26 hand-written scenarios. Its numbers describe those scenarios and
nothing else**, and say nothing about precision on real traffic: it was written alongside the
engine, by the same author, so it tests what that author thought of. It exists to pin behavior,
include attacks adapted to defeat the engine (a paraphrased destination, a poisoned instruction
file, a secret the redactor strips), and to be the thing a real adapter for AgentDojo,
SHADE-Arena or ControlArena plugs into.

### Measuring against AgentDojo

`agentdojo-convert` turns AgentDojo run logs into trajectories, and
`scripts/agentdojo-measure.sh` fetches the logs AgentDojo publishes for real models, converts
and replays them:

```sh
./scripts/agentdojo-measure.sh claude-3-7-sonnet-20250219          # one model, every suite
./scripts/agentdojo-measure.sh gpt-4o-2024-05-13/banking -v        # one suite, every scenario
AGENTDOJO_REF=089ed468 ./scripts/agentdojo-measure.sh ...          # pin upstream for a reproducible number
```

Each suite becomes an MCP server nobody has classified, so every tool result goes through
the untrusted-ingest path a deployment would use. AgentDojo labels runs, not calls, so the
adapter claims only what it can stand behind: a run whose injected attack succeeded is
hostile, a run with no injection is benign (and so is every call in it), and every other
injected run is left unlabeled. That covers failed attacks, DoS attacks, and errored runs,
which AgentDojo scores `security: true`. Attack runs mark their calls unlabeled, because
the only per-call label the log allows, "the arguments contain injected text", is the
signal the engine computes itself. [docs/03-detection.md](docs/03-detection.md#validating-the-detectors)
has the first results. They are the first numbers here not written by the engine's author,
and they are not flattering. SHADE-Arena and ControlArena have no adapter yet.

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

For a cohort, `ambitd` is installed as a scheduled task that starts at boot as SYSTEM, from an
Administrator PowerShell. The task's own restart-on-failure setting did not restart `ambitd` on a
Windows 10 test machine, so the installer also registers a repeating one-minute trigger with
`MultipleInstances` set to `IgnoreNew` and checks that it is there; the trigger worked once when
added by hand, and the installer's version has not yet run on a real machine (see
[Known limitations](#known-limitations)). It is a task and not a service because `ambitd` is a
console program, and making it a service would add a dependency:

```powershell
.\scripts\install-system.ps1 -Binary .\bin\ambitd-windows-amd64.exe
.\scripts\install-system.ps1 -Status
.\scripts\install-system.ps1 -Uninstall          # -Purge also removes the collected data
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

### Classifying MCP servers and tools

An MCP server nobody has classified is treated as the worst case: every call is untrusted
input and an external action (Rule-of-Two bits A and C). Two settings in `config.json` relax
that, and nothing else can: a server's own annotations never do.

```jsonc
{
  "trusted_mcp_servers": ["internal-wiki"],          // results are not untrusted input
  "mcp_tool_labels": {                               // per tool; globs allowed
    "bank": {
      "read_file":   ["untrusted", "read_only"],     // carries outside content: bit A, provenance ingest
      "get_balance": ["sensitive", "read_only"],     // reads private data: bit B
      "get_*":       ["read_only"],                  // labels from every matching entry combine
      "send_money":  []                              // classified: acts (bit C), carries neither
    }
  }
}
```

A labelled tool's bits come from its labels alone: `untrusted` sets A, `sensitive` sets B, and
anything not `read_only` sets C. A tool with no matching entry keeps the server's default, so
missing classification never relaxes anything. An unknown label or a malformed pattern is a
configuration error rather than a silent no-op. Leave `untrusted` off only for a tool whose
results can never contain text written by someone else. That is the label to get right,
because only untrusted results feed provenance. `testdata/agentdojo/mcp-tool-labels.json`
classifies AgentDojo's four suites and is what the measurements in docs/03 use.

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
| **M0 Observe** | `ambitd` hook endpoint and OTLP receiver, spool and Wazuh sink, edge redaction, keyed features, FIM and SCA artifacts. Every hook response is `{}`. | Implemented and tested. Installers run `ambitd` as a system service from boot (verified on Linux; not yet run on macOS or Windows). Not yet deployed to a cohort. |
| **M1 Inventory, drift, first rules** | `mcp-interpose` (D4 baseline, D5 metadata scan), Wazuh rules for D1–D12 with runbooks, SCA policies (an M0 subset for the observation-only bundle, and the full one). | Implemented. Rules validated offline against fixtures generated from the real pipeline; live-manager confirmation and an outside-analyst runbook test are open. |
| **M2 Provenance and Rule-of-Two, alert only** | Provenance engine, shadow-mode gates, replay harness. | Partial. Rule-of-Two bit accounting runs in shadow mode (`internal/r2`), and the gate runs in shadow too (`internal/gate`): docs/03's table is evaluated on every `PreToolUse` under per-session and per-turn scoping, and the verdict is recorded on the event (`policy_shadow=true`, rules 100320–100323) and never returned, so no session behaves differently. The provenance engine is implemented (`internal/prov`): it fingerprints untrusted ingest per session, intersects it with each `PreToolUse` input, and puts edges and taint labels on the event, alert-only via rule 100283. The replay harness is implemented (`cmd/ambit-replay`), with a hand-written starter corpus and an AgentDojo adapter measured against published runs of real models (docs/03). Precision on a real developer cohort is still unmeasured: that is what a shadow cohort is for. |
| **M3 Enforce** | Policy engine, signed policy bundles, split fail policy, containment-only active response. | Design only. |
| **M4 Goal drift** | Async scoring of actions against the stated objective. | Design only. |
| **M5 Fleet correlation** | Cross-session fingerprint set intersection; session-shape analysis. | Design only. |

Exit criteria gate each milestone. **M0:** a 5–10 endpoint volunteer cohort; p99 hook
response under 5 ms; zero developer-visible behavior change, verified by asking; local
spool event loss under 0.1%; the share of tool calls that cross to Wazuh measured
(design estimate 2–5%); and no
`Too many fields for JSON decoder` errors in the manager log. `ambitd report` on each endpoint
computes the latency, loss and fraction criteria from the spool. **M1:** every MCP server
the cohort uses inventoried with an approved baseline; a deliberately mutated server
triggers D4 within a session; killing `ambitd` fires D7 and stopping the Wazuh agent
fires rule 504; reverting a managed-settings key fires D12; and someone outside the
team executes a runbook against a sample alert.

## Known limitations

- **Deploy the M0 SCA policy for a cohort, not the full one.** The full policy asserts
  enforcement keys (bypass mode, sandbox, egress allowlist) that the observation-only M0
  bundle deliberately omits, so deploying both makes D12 fire on every endpoint. The `_m0`
  policy files assert only what the M0 bundle sets.
- **The system-service installers: Windows has run on one real machine, where the upgrade,
  restart and fresh install each passed once.** `scripts/install-system.sh` and `.ps1`
  install `ambitd` to run from boot, with the service manager set to bring it back if it
  exits. The Linux flow was run end to end against a stub service manager, and the systemd
  unit passes `systemd-analyze verify`. `install-system.ps1` was run on one Windows 10
  machine (see [Observed in a first lab run](#observed-in-a-first-lab-run)): the task, its
  principal, the data directory ACL and the managed settings came out as designed, but the
  configured restart-on-failure never restarted `ambitd`. The installer now registers a
  repeating one-minute trigger itself, disables the task before it replaces the binary, and
  refuses to finish if the registered task lacks the trigger. On the same machine an
  upgrade, a forced kill and an uninstall followed by a fresh install each passed once
  (observed); a new data directory, a reboot and which mechanism restarts `ambitd` are
  untested. The macOS installer has not been run on a real machine, and no Linux or macOS
  restart has been observed. See [docs/06-cohort-checklist.md](docs/06-cohort-checklist.md).
- **`SessionStart` reaches `ambitd` only through a `command` hook, and it carries no
  `permission_mode`.** Claude Code v2.1.278 fires it but does not deliver it to an `http` hook
  (observed in 3+ sessions, then isolated on Windows: the same event ran a `command` hook and
  never reached `ambitd` over `http`). Both bundles therefore register `SessionStart` as a
  command that runs `ambitd hook-forward`: the payload on stdin is posted unchanged to
  `ambitd`, nothing is printed (a SessionStart hook's stdout becomes model context), and the
  exit code is always 0, so a stopped `ambitd` costs one stderr line and never blocks a
  session. There is one bundle per OS family because the command names the installed binary by
  absolute path; like the `http` hooks it uses the default hook address. In the lab a
  `session_start` reached the spool this way (observed with a probe project; the installed
  bundle's exact command is untested). The real payload has no `permission_mode`, so rule
  100200, which needs `bypassPermissions` on a `session_start`, cannot fire on a live endpoint
  (inferred from the rule's condition). D1 rests on 100201 to 100203, which read the mode from
  tool events. The installers upgrade a managed-settings file that is exactly the earlier
  bundle and refuse to touch any other.
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
  the rules that use them. The array case has since matched on one fixture; see
  [Observed in a first lab run](#observed-in-a-first-lab-run).
- **MCP coverage is stdio only.** `mcp-interpose` is a stdio wrapper and does not cover
  servers reached over HTTP/SSE. `mcp_list` events usually carry no session id, because
  MCP does not carry one.
- **Native Windows has no OS sandbox.** Claude Code's sandbox runs on macOS, Linux and
  WSL2; on native Windows it runs commands unsandboxed, so detection is the only layer
  there and the detectors that read sandbox denials have no source. The Windows SCA
  policy omits the two sandbox checks because no configuration could satisfy them. Run
  inside WSL2 to get the sandbox. See [Windows](#windows).
- **Wazuh behavior on a Windows agent is mostly unconfirmed.** In a first lab run the agent
  logged that it opened `events.jsonl`. FIM wildcard expansion, log rotation under
  `log_format json`, SCA `f:` and `c:` rules and `whodata` have not been tried on a live
  agent, and each fails silently when wrong. See
  [deploy/wazuh/README.md](deploy/wazuh/README.md#windows-agents).
- **Provenance edges are evidence, not proof.** The intersection is an unsound approximation
  (CaMeL's dataflow tracking needs the interpreter, and Claude Code is a black box): the user
  may have supplied the value, the model may have reconstructed it, and a paraphrase defeats it
  entirely, so a missing edge means little. A value the ingest did not introduce (typed by the
  user, or passed in the same call) is excluded, which trades some recall for precision.
  Instruction files taint the session but contribute no fingerprints, because the hook carries
  a path and no content. The set is bounded; `prov_truncated` and `prov_evicted` in the
  shutdown log say when it was incomplete. Measured against AgentDojo's published runs, the
  edge cannot tell an agent legitimately carrying a value between tools from an injected one
  (a fifth of benign Claude 3.7 runs draw an edge), and it misses short values entirely. It
  sees checksum-valid IBANs, but not account numbers that are not IBANs, which includes
  AgentDojo's attacker account (no Claude 3.7 banking attack was caught). See [docs/03-detection.md](docs/03-detection.md#layer-2--provenance).
- **Sensitive-data edges are spool-only and match payloads by field name.** An acting call
  carrying a value a sensitive read returned is recorded as `provenance.exfil`, with no
  flattened field or rule yet. Only the call's payload is matched, not its addressing fields
  (`recipient`, `to`, `url` and similar), because addressing a known contact was as common in
  benign AgentDojo runs as in hostile ones. On GPT-4o banking it flags 136 of 553 successful
  attacks on the attacker's own payment against 1 of 25 benign runs. Hostnames are left out
  of the set, because they were most of the benign flags on Claude 3.7 and none of the useful
  matches; the cost is that on Claude 3.7 it now has no catch that provenance lacks. A tool
  that names its payload field like an address hides it, and a short value in a body (a
  security code) matches no fingerprint class.
- **Rule-of-Two session scoping is unresolved.** Bits are monotonic per session. A
  session that runs long saturates to all three, and `/clear` is reported to start a new
  session id, which would reset bits B and C that should not reset. Shadow mode exists
  to measure both, and the gate's verdict is computed under a per-turn scoping alongside
  for that comparison. See [docs/03-detection.md](docs/03-detection.md).
- **The gate depends on MCP tools being classified.** B comes from credential paths, reads
  outside the working directory, recognised secrets, and MCP tools labelled `sensitive`.
  Without labels, sensitive data arriving in a tool result sets nothing, and against
  AgentDojo's 2,626 published runs the gate never fired. With AgentDojo's tools labelled it
  catches 70% of Claude 3.7's successful attacks but also flags 42% of benign runs, because
  reading email and replying is a genuine Rule-of-Two case. It is measurable now, and not
  good enough to enforce.
- **The goal-drift pre-filter must key on an action's own Rule-of-Two bits**, never on a
  session-level transition, or it skips every repeat of an already-tripped bit.
  Operator `TrustedMCPServers` classification is the larger coverage risk: marking a
  same-vendor admin tool `internal` removes it from Rule-of-Two and goal-drift coverage.

### Observed in a first lab run

One run, by one person, in October 2026: Windows 10 Pro 22H2; `ambitd` built from commit
`32ee5399` with Go 1.26.7 (`go.mod` says 1.24); a single-node Wazuh 4.14.8 manager in Docker
and a Wazuh 4.14.8 Windows agent. Rules were exercised with `wazuh-logtest` on
`deploy/wazuh/fixtures/events.sample.jsonl`. Alerts from live events travelling from the
agent to the manager are described under the D2 sweep item below. Each item says whether it
was *observed* (seen directly), *inferred* (a reading of what was seen) or *untested*.

Worked as designed (observed): `go test ./...` passes natively on Windows (26 packages), and
`ambitd.exe` built there has the same SHA-256 as a Linux cross-build with `-trimpath
-buildvcs=false` and `CGO_ENABLED=0`. `install-system.ps1` created the task as SYSTEM with a
boot trigger, redirected the log through `cmd.exe`, restricted the data directory to SYSTEM
and Administrators, and installed a managed-settings file identical to the M0 bundle. The
Wazuh agent logged that it opened `events.jsonl`. All 43 fixture lines decode with the
built-in `json` decoder.

Open problems:

- **Rule 100204 stopped the manager loading `ambit_agent_rules.xml` (observed; fixed).** The
  pattern `^(ci|sdk)$` made `wazuh-analysisd -t` fail with `Syntax error on tag` for rule
  100204 and exit 1; changing only the pattern to `^ci$|^sdk$` made it exit 0. Renaming the
  field changed nothing. The other multi-value patterns in the rules are written without
  grouping, which fits Wazuh's default matcher not supporting it (inferred). The pattern is
  now `^ci$|^sdk$`, and `TestFieldPatternsAvoidGroupingParentheses` fails on any new field
  pattern with parentheses. The offline tests could not catch this before, because they
  compile patterns with Go's `regexp`, which accepts grouping. The fixed file was then read
  from the pushed branch and copied into the lab manager: its SHA-256 matched the hand-edited
  copy that had been running, and `wazuh-analysisd -t` exited 0 with the repo's file in place.
- **The Windows restart did not fire (observed; fixed, shown once).** With the task as
  installed, a forced kill was not followed by a restart in 90 seconds (`LastTaskResult`
  `0xFFFFFFFF`), and an invalid `config.json` made `ambitd` exit 1 and got one attempt in
  180 seconds, no retry. Adding a repeating one-minute time trigger, with
  `MultipleInstances` left at `IgnoreNew`, brought `ambitd` back about 55 seconds after a
  kill, with one instance and no duplicates. That was tried once, by hand. With that trigger
  in place, an upgrade failed: it restarted `ambitd` between the stop and the binary copy,
  so the copy hit a running file. The installer now registers the trigger itself (with a
  check that it is present), disables the task before stopping it and waits for the process
  to exit. On the same machine (observed, once each, 2026-10-22, Windows PowerShell 5.1):
  the first upgrade with that installer failed right after the kill with
  `The property 'Count' cannot be found on this object`, because the wait read `.Count` on
  an empty result under `Set-StrictMode`; its failure path re-enabled the old task and
  `ambitd` came back. With that fixed, the upgrade re-registered the task with the
  installer's own trigger and left one `ambitd` with an unchanged binary. The trigger's
  repetition came out as `P3650D`, so the installer's ten-year fallback was used, not the
  indefinite form (inferred). A forced kill then brought `ambitd` back in 40 to 45 seconds
  as one new instance, with no second one in the next 20 seconds. `-Uninstall` without
  `-Purge` removed the task, the binary folder and the managed settings and kept the data
  folder, and a fresh install restored all three byte for byte. Whether the repeating
  trigger or restart-on-failure brought `ambitd` back after the kill is untested.
- **`session_start` arrives through a command hook, with an empty mode (observed, 2026-10-22,
  Claude Code v2.1.278, Windows 10).** First run: in a throwaway project with both hook kinds
  registered, the `SessionStart` command hook ran and the `http` one added no `session_start`
  event, while the `SessionEnd` `http` hook did arrive. Built from the hook-forward commit and
  registered as a `SessionStart` command, `ambitd hook-forward` delivered one `session_start`
  to the spool with an empty `permission_mode`, about half a second before a PowerShell logging
  hook in the same group wrote its line (the hooks seem to start together; inferred). Second
  run, after `install-system.ps1` replaced the earlier bundle with the new Windows one (it
  recognised the old file by its SHA-256, one `ambitd` came back, and the installed command run
  by Git Bash exited 0, printed nothing and landed one synthetic `session_start`): a real
  session in an empty folder produced exactly one `session_start` (empty mode), two
  `prompt_submit`, a `Glob` `tool_pre` and `tool_post`, a `subagent_stop` and one
  `session_end`. Those events are attributed to the session by shape and timing, not by
  session id, because other Claude processes were open. `prompt_submit`, `tool_pre` and
  `session_end` all carried `permission_mode` `auto`, so a session's mode is first learned from
  its first prompt, not from `session_start` and not only after a tool call. The earlier
  probe session had two `session_end` events with identical timestamps; that did not recur in
  the clean run (cause unknown). Untested: the Linux and macOS bundle, and what the model
  sees at a session start.
- **The Windows FIM block was not deployed on the lab agent (observed).** Neither the
  agent's `ossec.conf` nor the manager's shared `agent.conf` named
  `C:\Program Files\ClaudeCode`, and the reinstall's delete and re-add of
  `managed-settings.json` raised no alert, so D6 rule 100254 has not fired live. Where the
  block is deployed it still does not watch `C:\Program Files\ambit`, so a replaced
  `ambitd.exe` would raise no FIM alert (observed in
  `deploy/wazuh/ossec-syscheck.windows.xml`).
- **The step 3 loop in docs/06 printed nothing on 4.14.8 (observed; replaced).** `wazuh-logtest -q`
  printed only blank lines for a fixture that fires rule 100201; the same line without `-q`
  shows the alert, on stderr. As written, the loop looked like a quiet fleet. It now points at a
  loop in `deploy/wazuh/README.md` that prints a line per fixture and was run in a container of the
  4.14.8 image (43 decoded as `json`, 33 alerts, 3 at level 0, 7 with no rule); it has not been run
  on the lab manager. A test fails if any documentation example uses `wazuh-logtest -q`.
- **Sibling rules shadow each other: one rule fires per event (observed).** A credential
  write in a `bypassPermissions` session alerted as 100201, not the D2 write rule 100212.
  An approved MCP tool with `hidden_instruction` alerted as 100241, not 100247, so 100247
  looks unreachable. Which rule wins is decided by level before file order (observed with
  `wazuh-logtest` on the 4.14.8 image, by swapping the order and levels of two identical
  rules): level 0 first, then the highest level, with file order only breaking ties. The
  live results above fit that and also fit "file order wins", because the winner was
  both earlier and higher.
- **The D2 sweep was blind in `bypassPermissions` sessions (observed live; fixed; the fix
  shown live, one session per mode).** Ten Read-tool reads of decoy credential files gave
  ten 100201 alerts and no 100211, because a bypass-mode read alerts as 100201 and 100211
  counted only 100210. A session that switched mode partway was blind the same way
  (observed offline).
  100211 now counts the group `ambit_cred_read`, carried by 100201 (now reads only) and
  100210; bypass-mode writes and other operations alert as a new 100205. Replayed through
  `wazuh-logtest` on the 4.14.8 image, 100211 fires on the 8th read in bypass, default and
  mode-switching sessions and never counts writes (`deploy/wazuh/fixtures/d2-sweeps.jsonl`).
  On the lab manager with the fixed rules loaded (100205 exists only in the fixed file),
  the 50-line fixture through one `wazuh-logtest` process gave 100201=19, 100205=15,
  100210=13 and 100211=3, the same tally as the offline image (observed). Two sessions then
  ran on the Windows agent (observed, one session each, 2026-10-22). In a
  `--dangerously-skip-permissions` session, ten Read-tool reads of the decoy files alerted as
  100201 x7, 100211 (level 12) on the 8th read, then 100201 x2, and the spool held ten
  credential Read `tool_pre` events with `permission_mode` `bypassPermissions`. In a session
  whose `permission_mode` was `auto`, the mode this PC starts in, ten reads gave 100210 x7,
  100211, 100210 x2. Alerts followed the spool events by 0.7 to 1.8 s, and reads issued in
  parallel did not change the count. A session in `default` mode has not been run; 100210
  has no `permission_mode` condition, so it should behave like `auto` (inferred; untested).
  The docs and fixtures do not mention `auto` yet. Other session shapes are untested.
- **`ignore` on 100211 silenced every other session's sweep (observed offline; removed).**
  After one session's sweep fired, a second session's sweep matched and raised no alert:
  `ignore` is per rule, not per `same_field` value. Without it, 100211 still fires once per
  eight fresh reads, not on every read.
- **Eight more correlation rules had the same `ignore`; removed (observed offline, wazuh-logtest
  4.14.8).** Two keys each sent the rule's threshold of events: with `ignore`, the second key's
  match was recorded as the rule with `alert=no` for 100221, 100301, 100252, 100292, 100240,
  100248, 100312 and 100261; without it both keys alerted. One key sent four times the threshold
  alerted four times (once per threshold), so removing `ignore` does not give one alert per
  event. 100261 was driven with a synthetic `policy_decision` of `fail_open`, since nothing emits
  it yet. Times were not varied: logtest replays instantly, so the 300 s windows were not tested
  (untested). The fixtures are `deploy/wazuh/fixtures/g-*.jsonl`, the recorded results `g-*.alerts`.
- **No correlation rule carries `ignore` with `same_field` now.** The last one, 100271, had
  `ignore="7200"` with `same_field` `agent.name`, the combination that silenced other keys in the
  correlation fixtures, so one agent's failing managed settings probably silenced every other
  agent's for two hours (inferred). It is removed. 100271 itself was not replayed (untested): it is
  a child of 100270, a child of Wazuh's SCA rule 19007, and `wazuh-logtest` decodes a raw SCA line
  with the generic JSON decoder (`check.id`, `policy_id`, `scan_id`), so 19006 and 19007 never match.
  The removal rests on the eight rules that were measured, and the lab plan should check it.
- **D10's two rules fire now (observed offline, wazuh-logtest 4.14.8).** On main they were dead:
  their parent 100280 was level 0, and level-0 matches are not counted by `if_matched_sid`.
  With 100280 at level 1, 100281 fired on nearly every repeat of a fingerprint and 100282 never
  fired, because 100281's alert replaces the events 100282 would count. The fix: 100281 now
  requires the same fingerprint in a *different* session (`not_same_field` on `session_id`),
  and 100282 counts 100281's matches, so it fires on the fifth sighting across sessions. No
  `ignore` on either. Eight scenarios, one logtest process each (`deploy/wazuh/fixtures/g-d10.*`):
  one session repeating a fingerprint 12 times raised nothing; twelve sessions each seeing it
  raised 9 alerts as 100281 and 2 as 100282; two fingerprints each seen in two sessions raised one
  alert each; three sessions seeing three different fingerprints raised none. The windows: the expiry mechanism was measured on wall-clock time with a 60-second copy of
100281's rule. A sighting 90 s after the first did not alert, and one 10 s after the second did, so
the window expires and a new one starts. The shipped 3600 s and 7200 s values use the same
mechanism but were not waited out; `deploy/wazuh/LAB-D10.md` step 5 checks them on the lab manager.
- **ambitd sends one `fp_sighting` event per session and fingerprint (unit-tested; not run
  against a live manager).** D10 counts these, not tool events. Without the once-per-session
  rule, a session that sees a fingerprint another session saw once keeps alerting: one session,
  then a second seeing it 20 times, gave 20 alerts (15 as 100281, 5 as 100282) from two
  sessions (observed offline). Each session remembers up to `fp_notable_session_cap`
  fingerprints (default 256) and forgets the oldest first, which can cost a repeat sighting and
  not a missed one; ambitd's memory resets on restart. The `tool_post` keeps
  `prov_fp_notable` on every sighting, so the spool has the full record; the `fp_sighting` goes to
  the SIEM only. A `tool_post` no longer crosses to the SIEM for its fingerprint alone. If the
  events sink refuses a sighting (its queue is full), the session clears its mark, so the next tool
  result that carries the fingerprint tries again (unit-tested with a sink that refuses, then
  recovers). Before this, measured with a sink that refused every write, a refused sighting was never
  sent again: the repeat wrote nothing. The retry needs the session to see the fingerprint again; if
  it never does, the sighting is lost. The spool still has the `tool_post` with its fingerprint, so an
  analyst can rebuild it by hand, and rule 100313 alerts on the drop.
- **A fingerprint is no longer lost to a louder alert on the same event (observed offline,
  constructed events).** While D10 counted `tool_post` events, a `tool_post` of a network `curl`
  carrying a secret alerted as 100302 and Wazuh never counted it toward 100281. With the
  sighting as its own event, twelve sessions whose even-numbered `tool_post` events alert as
  100302 gave all six 100302 alerts and 9 as 100281 and 2 as 100282, the same as without the
  collision. Two rules-only fixes were measured and rejected: counting a group shared by 100280
  and 100302 made 100281 replace the level 13 100302 alert whenever the event completed a pair,
  and restricting 100302 to `tool_pre` drops the alert for a secret that only appears in a
  command's result. Letting 100280 match both kinds would count every sighting twice (12 and 4
  instead of 9 and 2). A test fails if any other rule can match an `fp_sighting`. An ambitd
  build older than this sends no `fp_sighting`, so D10 does not count its hosts at all.
- **The lab manager runs none of this.** The image's default `log_alert_level` is 3, read from its
  `ossec.conf` (observed), so 100280 is silent by default. The lab's live setting was not read; the
  plan in `deploy/wazuh/LAB-D10.md` step 1 reads it.
- **Array matching works in the case tried (observed).** 100241, an unanchored literal,
  matched an event whose `mcp_scan_classes` is a two-element array. Only the first element,
  and one class at a time, were tried.
- **Fixture coverage is partial (observed).** Of 44 lines, 34 produced an alert, 1 matched a
  level-0 rule, 1 matched 100280 (the `fp_sighting`, level 1, counted and not alerted) and 8
  matched no rule. Rules 100203, 100204, 100210, 100211, 100212, 100221,
  100242 to 100245 and 100247 among others did not fire on any line. That is not a failure
  of those rules: the fixtures do not exercise them.
- **The hook response exceeded its latency budget (observed).** `ambitd` logged two lines
  with the same timestamp, `took=26.9995ms budget=5ms`. Whether that affects Claude Code, and
  whether the two lines are two requests, is untested.
- **OTLP is off, but the M0 bundle points telemetry at it (observed configuration).**
  `install-system.ps1` writes no `config.json`, so `ambitd` logs `otlp_addr=off`, while the
  bundle sends telemetry to `127.0.0.1:4318` and the SCA policy has checks that expect it.
  What Claude Code does when that export is refused is untested.
- **The data directory is readable only by SYSTEM and Administrators after
  `install-system.ps1` (observed).** The comment in
  `deploy/wazuh/ossec-localfile.windows.xml` says the ACL also grants the current user.
  The agent runs as SYSTEM and can read it; a non-elevated user cannot.
- **A `sink_gap` marker line matches no rule (observed; intent unclear).** The docs pair the
  markers with rule 100313, which matches `health_dropped_events` on an `ambitd_health`
  event, not the marker itself.
- **The hook payload key names were wrong for the prompt, the tool output and the tool error
  (observed; fixed).** In a real session both `prompt_submit` events had `prompt.bytes` 0 and no
  text. A probe that recorded only key names and value types on Claude Code v2.1.278 (Windows,
  2026-10-22) showed it sends `prompt`, `tool_response` (an object for a Bash call: `stdout`,
  `stderr` and three booleans) and `error`, where the code read `user_input`, `tool_result`
  and `tool_error`; it also sends `reason` for `SessionEnd` and `trigger` for the compact
  events. Because tool output was never read, provenance ingest recorded nothing on real
  sessions (inferred from the code path; no missed alert was observed). The collector now
  reads the real names and still accepts the old ones. Its tests are built from the recorded
  key sets (`internal/hook/testdata/claude-code-2.1.278-shapes.txt`), and replaying the corpus
  with the real names failed 14 of 26 scenarios on the old code. Live check (2026-10-22, one
  Windows machine): with a build that has the fix installed, a real session recorded its two
  prompts at 31 and 88 bytes, as typed, and found a marker word in their stored text; a Bash
  call's tool output was counted at 30 bytes, larger than the 19 bytes the command printed
  (the difference is unexplained). Before the fix the same fields were 0. Untested:
  `PermissionRequest`, `PermissionDenied` and `ConfigChange` were not triggered, so
  `config_source` and `change_type` are still unverified names.

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

The Go packages, `smoke.ps1`, `dev-local.ps1` and the interposer's end-to-end behavior are
exercised on a real Windows host by the `windows` job in
`.github/workflows/check.yml`, under Windows PowerShell 5.1 and PowerShell 7. That covers
`ambitd`, `mcp-interpose` and the local install; it does not cover a Wazuh agent on
Windows, and Claude Code's own hook payloads on Windows were read from its documentation
rather than captured. `install-system.ps1` is parsed by PowerShell 7 in CI; it has been run
on one Windows 10 machine, for a first install, an upgrade and a fresh install (see
[Observed in a first lab run](#observed-in-a-first-lab-run)).

The comment removal was checked rather than assumed. The Go replay reports (the starter corpus
and both AgentDojo model runs) are byte-identical before and after, the set of files compiled
on each OS is unchanged, and PowerShell's own tokenizer sees the same non-comment tokens in
every `.ps1`.

## License

MIT. See [LICENSE](LICENSE).
