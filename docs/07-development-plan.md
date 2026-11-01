# 07 — Development plan

What comes next for ambit, in order, and who can do each part. The [README](../README.md#roadmap)
holds the milestones and their exit criteria, and [TODO.md](../TODO.md) holds the checklist with a
box for each result someone has seen. This document is the order of work between them: what to land,
what to run, what to decide, and what to build after the evidence comes in.

Each item says who it needs:

- **Code**: work that can be written and tested from the repository alone, against fixtures, fuzzers
  and the replay corpus. It ends in a branch and a pull request.
- **Machine**: needs a real endpoint, a Wazuh manager, a Windows or macOS host, or a live MCP server.
- **Cohort**: needs volunteers running ambit for days, and someone reading what it produced.
- **Decision**: needs the owner to choose between options with different costs. Nothing gets built
  until the choice is made.

## Stage 1 — Land the open branches

Ten branches are pushed and not yet merged. Each was cut from `main` at the same commit. Each passed
`go vet`, gofmt, staticcheck and the tests of the packages it touches on its own. Merged together
they merge cleanly and pass the whole suite, including the race tests, the smoke tests and
`make lint`. CI runs the rest on each pull request.

| Branch | What it does |
| --- | --- |
| `ambit-staticcheck-ci` | Runs staticcheck in CI (`make lint`). Fixes a fuzz check that compared a hash with itself and so could never fail. |
| `ambit-registrable-public-suffixes` | `bbc.co.uk` and `mycompany.github.io` stay separate registrable domains. Before, trusting one GitHub Pages site trusted all of them, and every ngrok tunnel was one D9 destination. |
| `ambit-doctor-mcp-coverage` | `ambitd doctor` says which MCP servers are behind `mcp-interpose`, which are not, and which use a `-server` name that differs from the key. |
| `ambit-labelsuggest-reference-servers` | `-suggest-labels` is tested against the reference MCP servers' tool names. It skips a server-name prefix and never suggests `read_only` for a tool that fetches an address the agent supplies. |
| `ambit-egress-fuzz` | Fuzz targets for the egress profile and the sandbox target parser. They found two bugs, fixed on the same branch. |
| `ambit-config-egress-path-check` | Refuses an `egress_profile_path` that points at a sink or the HMAC key. |
| `ambit-replay-egress-scenarios` | Two replay scenarios that pin D9's destination profile, one benign and one attack. |
| `ambit-runbook-d9-egress` | The D9 runbook uses `egress_destination` in triage and says where to read it. |
| `ambit-interpose-header-secret-check` | `mcp-interpose -header` refuses a credential header and points to `-header-env`. |
| `ambit-development-plan` | This document. |

Two branches touch the same part of a file, but in different hunks:

- the Makefile: staticcheck and egress-fuzz
- the README: doctor, labelsuggest, replay and the header check

**Done when:** all ten are merged and CI is green on `main`.

**Who:** you, after review. A merge conflict or a CI failure is code work.

## Stage 2 — Decide

These choices block later work. Each one lists its options.

1. **Can anyone see `egress_destination` on the manager?** *Decided: yes.* The manager keeps only
   events a rule matches, because archiving is off by design
   ([deploy/wazuh/README.md](../deploy/wazuh/README.md#do-not-enable-archiving)). So without a rule,
   the shadow event reached Wazuh and was dropped there. Rule 100306 now stores it at level 3,
   informational and never paged, so the cohort can be reviewed from one place. Its winner in
   `events.sample.winners` is the Go model's answer until someone re-records it with
   `wazuh-logtest`; this needs Docker (stage 3).
2. **Should WebFetch and WebSearch feed the egress profile?** D9 profiles Bash network commands and
   sandbox denials, which were the two sources chosen. A WebFetch to a new host is also a first
   contact, but it never reaches the profile. Adding it is a small code change and a new
   `egress_source` value.
3. **Should a learning period come before any D9 alert?** For example, the first N days, or the
   first M destinations, on each endpoint. The answer depends on the cohort's numbers (stage 4),
   but the shape of the rule depends on this choice.
4. **Which tenancy model for third-party monitoring?** The options are in
   [02](02-architecture.md#tenancy-for-third-party-monitoring). This blocks any MSSP pilot.

## Stage 3 — Verify on real machines

Everything below is built and tested against fixtures or stand-ins, never against the real thing.
TODO.md sections 1 and 2 hold the detail. In order of what blocks the most:

| Item | Who | Done when |
| --- | --- | --- |
| Linux restart under systemd: `sudo ./scripts/verify-restart.sh` | Machine | The script passes on a test machine with the installed unit |
| Every Wazuh fixture through `wazuh-logtest`: `sudo ./scripts/verify-manager.sh` | Machine | It passes on the manager, with no `-q` |
| Rule 100306's winner recorded, not predicted: `./scripts/record-winners.sh events.sample` | Machine with Docker | `events.sample.winners` line 55 reads 100306 from logtest, and its header note is gone |
| The three silent Wazuh behaviors: the syscheck parent SIDs, the SCA parent SID, and how a `<field>` regex matches an array | Machine | Each is confirmed on the deployed manager version |
| A live `SessionStart` through `hook-forward`, and rule 100200 firing from a real session | Machine | An alert is seen for a real session |
| `mcp-interpose -url` against a real remote server, over Streamable HTTP and over HTTP+SSE | Machine | Both transports run a session, and `-show` lists the tools |
| Windows: restart, the installer's `ambitd stop` path, a fresh data directory with a reboot, and the FIM and SCA behaviors on an agent | Machine | Each one runs once on Windows PowerShell 5.1 under the task scheduler |
| macOS: the installer end to end, and a restart | Machine | Each one runs once on a real Mac |
| M4 goal drift against the real Messages API | Machine | Scores arrive on an endpoint and cross above the threshold |

Code can help here without running anything live. When a run fails, the fix is code work: send the
failing output, and it can be reproduced against a fixture and fixed.

## Stage 4 — Run the M0 cohort

TODO.md section 3, in order:

1. **Your own machine first.** Run `make check && make smoke`, then a few days on `dev-local`. Read
   `events.jsonl` as an analyst would.
2. **Volunteers.** Recruit 5–10 volunteers who have been told what is collected. Deploy the M0 SCA
   policy, never the full one. Decide whether there is one fingerprint key or one per endpoint
   before the first start.
3. **Measure the exit criteria** with `ambitd report` on each endpoint:
   - p99 hook response under 5 ms
   - spool loss under 0.1%, with the restart count stated beside it
   - the interesting fraction, compared with the 2–5% estimate
   - no `Too many fields for JSON decoder` in the manager log
   - zero developer-visible change, confirmed by asking each volunteer
4. **Read D9's shadow data.** How many `egress_destination` events per endpoint per day? How many in
   the first week, against later weeks? Which were email domains from a request body, rather than
   hosts? This is the input to decision 3 and to the first D9 rule.
5. **Record the cohort's MCP tool lists.** Run `ambitd doctor` in each project to confirm the
   servers are interposed. Then run `mcp-interpose -suggest-labels`. Add each server's tool list to
   `internal/labelsuggest/reference_test.go`, and correct the heuristics where they guess wrong.

**Who:** cohort for the runs, and you for the reading. Code for every fix the readings turn up.

## Stage 5 — Exercise the M1 detectors

TODO.md section 4. On the manager, start `sudo ./scripts/expect-alert.sh --rule N --agent NAME`,
then cause each condition:

- **D4:** a mutated test server fires D4 (100234) in the same session.
- **D7:** killing `ambitd` fires D7 (100314), and stopping the agent fires rule 504.
- **D12:** reverting a managed-settings key fires D12 (100270).
- **Runbooks:** someone outside the team works a runbook from a real alert.

**Who:** machine and cohort.

## Stage 6 — Build on the evidence

These items wait on stages 3–5, because their correct form depends on what those stages show.

| Item | Needs first | Who |
| --- | --- | --- |
| The first D9 destination rule, with a learning period | Decisions 1 and 3, and stage 4's numbers | Code |
| D9 volume profiling | A way to get byte counts. The hook does not carry them, and OTel may. | Decision, then code |
| WebFetch and WebSearch in the egress profile | Decision 2 | Code |
| M2 precision on a real cohort, and Rule-of-Two scoping across `/clear` and long sessions | Stage 4 | Cohort, then code |
| An emitter for `agent_entrypoint`, which would make rule 100204 live | A Claude Code payload that carries it. None has been found. | Machine, then code |
| MCP servers that need Claude Code's OAuth sign-in | A design: the interposer cannot run Claude Code's sign-in flow | Decision, then code |
| A full public suffix list, if the short one proves too short | Stage 4 shows destinations merged under an unlisted suffix | Code |
| SHADE-Arena and ControlArena adapters for replay | Run logs from those projects; neither repository ships them | Data, then code |
| M3 enforce, starting at `ask` and never at `deny` | Two weeks at `ask` on reviewed evidence for each rule | All four |
| M5 fleet correlation | M3 and the cohort's fingerprint data | All four |

## Code work that needs nothing above

These items can start at any time, each on its own branch:

- `mcp-interpose -url` in the smoke script, run against a small HTTP MCP server the script starts.
  Today the HTTP bridge is covered only by Go tests.
- `govulncheck` in CI. The development environment's proxy refuses `vuln.go.dev`, so it was not run
  for this plan; GitHub's runners can reach it.
- `mcp_list` events that say whether a server is local or remote. An analyst triaging D4 on a
  remote server has different questions to ask. This adds a field, so it needs a check against the
  field ceiling.
- An `ambitd doctor` check that the egress profile loads, so a damaged profile shows up before
  someone wonders why D9 is quiet.

## Errata

The commit message on `ambit-egress-fuzz` says that Claude Code's sandbox block would carry a Unicode
hostname in its ASCII form. That has not been observed. The code refuses a Unicode hostname either
way, so only the sentence is wrong. Fixing it would mean rewriting the branch's pushed history, so it
is recorded here instead.
