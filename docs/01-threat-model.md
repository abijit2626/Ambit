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

## The monitor is a target — and now partly outside our control

This system observes every file the agents read and every argument they pass. That
makes it the most sensitive data store in the deployment and an attractive target in
its own right — and a hijacked agent's most valuable move is to blind or plunder it.

Two things changed when the fleet plane became Wazuh with third-party monitoring:
**a copy of the data leaves our control**, and **the monitoring channel now runs in
both directions** ([02](02-architecture.md)).

### Digests-only becomes a contractual requirement

Where digests-at-the-edge was previously a good internal hygiene decision, it is now
the mechanism by which an external security firm can monitor the deployment without
receiving a map of our source tree, our credential layout, and every domain our
agents touch. It is a term of the engagement, not a preference.

The tension this creates is real and has to be resolved rather than waved at: **an
external analyst who cannot resolve a path digest cannot triage.** An alert reading
"read of `hmac:9f3a...` followed by outbound network" is unactionable. Resolution:

- **Zone labels in cleartext.** Every path carries `credential`, `workdir`,
  `untrusted`, `system`, or `home`. This is the field that carries the security
  meaning — "a credential-zone read preceded egress" is triageable without knowing
  the filename, and it is the field the detectors key on anyway.
- **Paths as keyed digests.** HMAC with a per-org key **we hold and the firm does
  not**, so equality-matching across events still works (D10's tripwire depends on
  it) while offline dictionary attacks on short low-entropy values do not.
- **Digest resolution runs on our side, on request.** A documented request path with
  a real turnaround, not a note in a runbook saying "ask the customer." This is a
  standing operational commitment and the thing most likely to be under-resourced.
- **Every runbook is written for an analyst who cannot see our source tree**
  ([03](03-detection.md)). A runbook whose first step requires cleartext is a broken
  runbook, and the way to find out is to have someone outside the team execute it
  against a sample alert before the detector ships.

The residual is that zone labels leak structure — knowing an endpoint had forty
credential-zone reads today is itself information. That is an acceptable disclosure
to a firm engaged to watch for exactly that, and it is the floor: below it, external
monitoring does not function.

### What the MSSP must not receive or be able to do

- **No trajectory spool, no content blobs, no path-digest reverse maps.** They see
  the Wazuh copy: the digest-bearing event and alert stream
  ([04](04-data-model.md)).
- **No HMAC key.** Equality without resolution.
- **No active-response dispatch.** The manager can execute scripts on every enrolled
  endpoint, which makes manager access a fleet-wide code-execution primitive.
  Containment is ours to execute on their recommendation ([02](02-architecture.md)).
- **No ability to change the inline gate.** Policy bundles travel a path separate
  from Wazuh's centralized configuration, deliberately.

Every one of these is a policy control enforced through Wazuh RBAC, agent groups, and
index-level restrictions — and Wazuh's multi-tenancy is thin. The controls are only as
good as the tenancy model, which is unresolved and needs an owner
([07](07-open-questions.md) Q11). Until it is settled, treating these as *enforced*
rather than *intended* would be overclaiming.

### Still true

- **Redact at the endpoint.** Secrets must never leave the machine in cleartext, and
  now must never reach the MSSP in any form.
- **Separate credentials and separate blast radius** from the agent fleet. The
  manager's credentials must not be reachable from any endpoint it monitors.
- **An agent that can write to its own monitor can poison its own audit trail.** The
  pre-Wazuh design got this with a write-only ingest endpoint. That property is
  weakened now — the Wazuh agent's enrollment key sits on the endpoint, so adversary
  A1 can speak to the manager as that agent. [02](02-architecture.md) covers the
  partial mitigations and states plainly that this is a regression with no clean fix
  on a compromised endpoint.

## Attack paths this design is meant to break

| Path | Where it breaks |
| --- | --- |
| Malware invokes agent with bypass flags → reads `~/.ssh` → `curl` to attacker host | `disableBypassPermissionsMode` in managed settings; sandbox egress allowlist; "session with no human" detector; Rule-of-Two gate on read-secrets-then-egress |
| Injected instruction in a fetched page → agent writes exfil to a public repo | Provenance edge from ingest to action; Rule-of-Two third-bit gate on external communication after untrusted ingest |
| Poisoned MCP tool description → agent passes credentials to attacker's tool | MCP interposer inspects and hashes descriptions at list time; drift alert against the approved baseline |
| Rug pull on an approved server | Tool metadata hash comparison on every session start |
| Decomposed malicious campaign | Fleet-level session-shape analysis; goal-drift scoring; aggregate review, not per-action blocking |
| Cross-agent propagation | Content fingerprint matching between one session's ingest and another's output |
| Malware edits agent config to disable hooks or widen permissions | Wazuh FIM with `whodata` on `.claude/` and `.mcp.json` reports which process wrote it; SCA asserts the managed bundle is still correct (D12); `ConfigChange` covers in-session changes that never touch disk |
| Attacker kills the monitoring to work unobserved | Wazuh agent-disconnect alerting (rule 504, T1562.001); SCA `p:ambitd` liveness from a separate process; fail-open run detection (D11); inconsistency between four independent streams |

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
- **A compromised Wazuh manager, or a malicious operator with manager access.**
  Active response makes the manager a fleet-wide code-execution primitive. The
  endpoint-side script allowlist bounds what can be run, and withholding dispatch
  permission from MSSP roles bounds who can run it, but neither removes the
  primitive. This is a capability the pre-Wazuh design did not have and it is the
  clearest cost of the change.
- **Forged events from a compromised endpoint.** The Wazuh agent's enrollment key is
  on the endpoint, so adversary A1 can inject fabricated events or flood to bury real
  ones. Per-agent keys scope forgery to one endpoint and volume baselining makes a
  flood visible, but a patient attacker forging a plausible low-volume stream is not
  detected. A regression against the write-only ingest design, stated rather than
  solved.
- **Anything the tenancy model is supposed to enforce but does not.** The MSSP
  restrictions in this document are policy controls resting on Wazuh RBAC, agent
  groups, and index restrictions. Wazuh's multi-tenancy is thin
  ([07](07-open-questions.md) Q11); until that is settled these are intentions, not
  guarantees.
