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

*Done.* Every branch this plan started with is merged, and so is the code work it listed as
needing nothing else: `govulncheck` in CI, the `mcp-interpose -url` smoke test, local or remote
on `mcp_list`, and the doctor check that the egress profile loads. Later rounds added, among
others:

- `ambitd report` counts D9's new destinations per day, and compares the first week with later
  ones
- `ambitd doctor` checks that ambitd's files are private and warns on `-url` over plain http
- the hourly health event carries the egress profile's state
- D9 no longer counts email domains or URL path words as destinations
- the Bash classifier reads through runners (`sudo -u`, `timeout`, `xargs`, `find -exec`, ...),
  and through code given to an interpreter on the command line (`python -c`, `node -e`, ...)
- CI fuzzes every target by a count of inputs, so a slow input cannot fail it on time alone

New work follows the same rule: one branch per change, cut from `main`, merged once CI is green.

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
   but the shape of the rule depends on this choice. `ambitd report` shows, on each endpoint, how
   many alerts a rule on every new destination would have fired after a learning period of 0, 3,
   7, 14 and 30 days, and how many a day.
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
4. **Read D9's shadow data.** `ambitd report` on each endpoint gives the new destinations per day,
   by source, and the first week's daily rate against later weeks'. Read a sample of the
   `egress_destination` events beside it: which were hosts nobody contacted, read from text that
   only named them? This is the input to decision 3 and to the first D9 rule.
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

Nothing is waiting here at the moment. What remains is in the stages above, which each need a
machine, the cohort or a decision first. The likeliest code work while those run:

- **A fix for each failure a stage 3 or stage 4 run turns up.** Send the failing output; it can
  be reproduced against a fixture and fixed on its own branch.
- **The classifier's known gaps** ([README](../README.md#known-limitations)): a script file, code
  that reaches the network through a subprocess, and runners outside its table, such as GNU
  `parallel`. Close them when the cohort's commands show they matter.
- **Longer fuzz runs.** `make fuzz` runs 100,000 inputs per target, ten times CI's round. Every
  run so far that went past CI's count found a classifier bug, so it is worth repeating after
  each classifier change.

## Errata

The commit message on `ambit-egress-fuzz` says that Claude Code's sandbox block would carry a Unicode
hostname in its ASCII form. That has not been observed. The code refuses a Unicode hostname either
way, so only the sentence is wrong. Fixing it would mean rewriting the branch's pushed history, so it
is recorded here instead.
