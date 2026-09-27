# 01 — Threat model

## Scope

**In scope:** Claude Code and other CLI coding agents running on developer
endpoints and CI runners, and the MCP servers they connect to.

**Out of scope for this design:** web-surface agents (claude.ai), IDE-only
assistants without tool access, and agents we do not operate. Also out of scope:
solving prompt injection. There is no known complete defense; every mitigation
here is blast-radius reduction.

## Assets

| Asset | Why an attacker wants it |
| --- | --- |
| Source code, including private repos | IP theft, finding further vulnerabilities |
| Credentials on the endpoint: SSH keys, `.env`, cloud config, `.npmrc`, GitHub/npm tokens, keychain items | Lateral movement; this is what s1ngularity actually took |
| The agent's authenticated reach: git push, cloud APIs, MCP-connected SaaS | Acting as the developer |
| CI/CD write access | Supply-chain persistence |
| The monitoring plane itself | See "The monitor is a target" below |

## Adversaries

### A1 — Endpoint malware using the agent as a tool
The s1ngularity pattern. Code already executing on the endpoint (via a
compromised dependency, a post-install script, a malicious VS Code extension)
invokes the agent CLI directly, non-interactively, with permission bypass, and
uses its filesystem access and reasoning to find and stage secrets.

*Capability:* arbitrary local code execution as the developer. Can read and write
user-scope config. Can kill local processes.

*Key signature:* **an agent session with no human in it.** Non-interactive
entrypoint, `permission_mode` of `bypassPermissions`, `SessionStart` with no
following `UserPromptSubmit`, immediate high-volume reads of credential paths.

### A2 — Indirect prompt injection from ingested content
Instructions planted in data the agent reads as part of legitimate work: a web
page, a GitHub issue or PR body, a code comment, a dependency's README, a CI log
line, an MCP tool result, an email. The agent is doing the task it was given; the
content redirects part of what it does.

*Capability:* no code execution. Only the ability to get text in front of the
model, and only the agent's own permissions thereafter.

*Key signature:* an action whose arguments derive from recently-ingested untrusted
content, or which does not serve the stated objective.

### A3 — Malicious or compromised MCP server
Tool poisoning (adversarial instructions in tool descriptions, parameter schemas,
or results — free-text fields with no length limit, schema validation, or
sanitization), rug pulls (benign at review, malicious after an update),
cross-server shadowing (one server's description changing agent behavior toward
another's tools), and name-squatted or unsanctioned shadow servers.

*Capability:* controls everything it advertises and returns. Sees every argument
passed to it.

*Key signature:* tool metadata that changed since approval; description text
containing instruction-shaped language; a server's results correlating with
subsequent actions against unrelated tools.

### A4 — Task-decomposition abuse by an authorized user
The GTG-1002 pattern, and the insider case. A person with legitimate access
breaks a prohibited objective into steps that each look defensible, and supplies
a framing ("we are the security team, this is authorized testing") that makes them
read as legitimate in isolation.

*Capability:* full legitimate access. Controls the prompts.

*Key signature:* only visible in aggregate — the shape of a session or a set of
sessions, not any single action. This is the hardest of the four and the one that
most requires fleet-level history.

### A5 — Cross-agent propagation
A compromised agent's output becomes another agent's input: a PR description, a
commit message, a shared task queue, a ticket, an agent-to-agent message. The
"Prompt Infection" work (Lee & Tiwari, arXiv:2410.07283) demonstrates
self-replicating LLM-to-LLM injection spreading across a multi-agent system, and
notes the counter-intuitive result that more capable models spread it more
effectively.

*Capability:* whatever the first compromise had, multiplied by fleet size.

*Key signature:* the same distinctive content appearing as an ingest in one
session and an output in another.

## Explicit trust assumptions

Stated plainly, because the design depends on them and two of them are weak:

1. **The endpoint OS is not assumed trustworthy.** A1 has code execution there.
   Anything running locally can be killed. This is why the fleet plane treats
   *silence as a signal* and why policy is delivered through managed settings
   rather than files the developer (or malware running as them) can edit.
2. **Claude Code itself is assumed to behave as documented.** Hooks fire,
   managed settings take precedence, the sandbox holds. If the binary is replaced,
   nothing here helps. Binary integrity is an endpoint-management problem, not
   ours — but we should report the version and path we observe so a substitution
   is at least visible.
3. **The model is not assumed adversarial.** We are defending against content and
   operators that hijack the agent, not against the model pursuing its own hidden
   goals. This matters because it lets us use the model's own declared objective
   as a reference point for goal-drift detection. If the threat model shifted to
   an adversarial model, that detector becomes unsound and the AI-control
   literature (untrusted monitoring, defer-to-trusted, collusion risk) becomes the
   relevant frame instead. Noted as a boundary, not addressed.
4. **MCP servers are untrusted by default,** including ones previously approved,
   because of rug pulls.

## The monitor is a target

This system observes every file the agents read and every argument they pass. That
makes it the most sensitive data store in the deployment and an attractive target
in its own right — and a hijacked agent's most valuable move is to blind or
plunder it.

Design consequences, non-negotiable:

- **Redact at the endpoint.** Digests by default, content only under explicit
  policy. Secrets must never be shipped to the fleet plane in cleartext.
- **The fleet plane must not be reachable from the agents it monitors.** Ingest is
  one-way: a write-only ingest endpoint, on a network path the sandbox's egress
  allowlist does not grant to agent subprocesses. An agent that can `POST` to its
  own monitor can poison its own audit trail.
- **Separate credentials and separate blast radius** from the agent fleet. The
  monitor's credentials must not be reachable from any endpoint it monitors.

## Attack paths this design is meant to break

| Path | Where it breaks |
| --- | --- |
| Malware invokes agent with bypass flags → reads `~/.ssh` → `curl` to attacker host | `disableBypassPermissionsMode` in managed settings; sandbox egress allowlist; "session with no human" detector; Rule-of-Two gate on read-secrets-then-egress |
| Injected instruction in a fetched page → agent writes exfil to a public repo | Provenance edge from ingest to action; Rule-of-Two third-bit gate on external communication after untrusted ingest |
| Poisoned MCP tool description → agent passes credentials to attacker's tool | MCP interposer inspects and hashes descriptions at list time; drift alert against the approved baseline |
| Rug pull on an approved server | Tool metadata hash comparison on every session start |
| Decomposed malicious campaign | Fleet-level session-shape analysis; goal-drift scoring; aggregate review, not per-action blocking |
| Cross-agent propagation | Content fingerprint matching between one session's ingest and another's output |

## What this design does *not* break

Being honest about residual risk:

- **A fully compromised endpoint.** We make compromise visible and raise its cost.
  We do not make the endpoint trustworthy. Local enforcement on a machine the
  attacker owns is defense in depth, not a boundary.
- **Paraphrased exfiltration.** Content-fingerprint provenance catches literal
  carry-through of a domain, URL, key, or blob. A model that re-words the
  attacker's instruction into its own text defeats it. Session-level taint still
  applies; the specific edge is lost.
- **Low-and-slow abuse by an authorized operator (A4)** below the threshold of
  aggregate analysis.
- **Anything inside an encrypted tunnel to an allowed domain.** The sandbox proxy
  makes its allow decision from the client-supplied hostname and by default does
  not terminate TLS, so domain fronting can reach hosts outside the allowlist, and
  a broad entry like `github.com` is itself an exfiltration path. TLS-terminating
  inspection requires a custom proxy with its CA installed in the sandbox.
