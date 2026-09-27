# indirect-prompt

A fleet-level provenance and control plane for Claude Code and MCP servers.

## The problem

A company runs many coding-agent instances. Each one holds a developer's
filesystem access, credentials, and network reach. Each one continuously ingests
untrusted content — web pages, issue bodies, dependency source, MCP tool results,
CI logs. Any of that content can carry instructions.

The documented attacks are not hypothetical:

- **s1ngularity** (August 2025): malicious `nx` npm versions shipped a
  `telemetry.js` post-install script that looked for locally installed AI CLI
  agents (Claude, Gemini, Amazon Q) and re-invoked them with permission-bypass
  flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) to
  inventory and exfiltrate SSH keys, `.env` files, and cloud credentials to
  attacker-visible public GitHub repos. Malware using the developer's own agent
  as its recon tool.
- **GTG-1002** (disclosed 13 November 2025): a state-linked actor decomposed an
  espionage campaign into thousands of individually innocuous subtasks and framed
  the session as authorized penetration testing, getting Claude Code to execute
  an estimated 80–90% of the intrusion across ~30 targets with humans at only
  4–6 decision points.
- **MCP supply chain**: tool poisoning (adversarial text in tool descriptions and
  schemas), rug pulls (a server approved benign, updated malicious), and
  cross-server shadowing (one server's description altering behavior toward
  another server's tools).

The unifying shape: **the agent's actions stop serving the task it was given, and
each individual action still looks legitimate.** The research consensus is that
reasoning-level monitoring is a weakening signal and *action*-level monitoring is
the durable one.

## What this is

Claude Code already ships a strong *preventive* layer: an OS-enforced Bash
sandbox with filesystem and network isolation, an egress allowlist with managed
lockdown, credential masking with proxy-side injection, deny rules that managed
settings pin above every other scope, and 33 hook events that can block a tool
call before it runs. See [docs/06-prior-art.md](docs/06-prior-art.md).

What does not exist, and is therefore what this repo builds:

1. **Provenance.** Nothing links "this agent ingested untrusted content" to "this
   agent then took this action." That link is the highest-value detection signal.
2. **Rule-of-Two accounting at runtime.** The three properties are observable from
   the hook stream; nothing tracks them per session or gates on the third.
3. **Fleet aggregation.** N agents are N isolated policy islands with no shared
   history, no cross-session correlation, and no drift detection.
4. **Goal-drift detection.** Nothing scores an action against the objective the
   user actually stated — the covert-side-task signal.
5. **MCP change detection.** Nothing notices that a server's tool descriptions
   changed between the review that approved it and the call that trusts it.

The system is therefore a **consumer and configurator of Claude Code's existing
primitives, not a replacement for them.**

## Documents

| Doc | Contents |
| --- | --- |
| [01-threat-model.md](docs/01-threat-model.md) | Adversaries, assets, attack paths, what is explicitly out of scope |
| [02-architecture.md](docs/02-architecture.md) | Components, interception points, trust boundaries, latency and failure modes |
| [03-detection.md](docs/03-detection.md) | Provenance graph, Rule-of-Two accounting, detector catalogue |
| [04-data-model.md](docs/04-data-model.md) | Normalized event schema, redaction, retention |
| [05-build-plan.md](docs/05-build-plan.md) | Staged milestones, observe-before-enforce sequencing |
| [06-prior-art.md](docs/06-prior-art.md) | What already exists, what we reuse, non-goals |
| [07-open-questions.md](docs/07-open-questions.md) | Unresolved design decisions needing a call |

## Status

Design only. No implementation code yet. Nothing here is committed to as final —
[07-open-questions.md](docs/07-open-questions.md) lists what still needs deciding.

## Sourcing note

Claims about Claude Code's hooks, permissions, sandboxing, telemetry, and managed
settings were verified against the official documentation at `code.claude.com`
during research and are cited inline. Claims about published incidents, MCP
threat classes, and academic work are cited to the source that supports them.
Where a claim rests on a secondary source or a post-May-2026 publication that
could not be fetched directly, it is marked *(unverified)*.
