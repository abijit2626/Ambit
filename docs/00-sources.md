# 00 — Sources

Everything the design rests on, with its verification status. Claims marked
**primary** were fetched and read during research. Claims marked **secondary** come
from search results summarizing a source that could not be fetched (several domains
are blocked by this environment's egress proxy). Claims marked **unverified** should
not be relied on without checking.

## Claude Code — all primary

- [Hooks reference](https://code.claude.com/docs/en/hooks) — the 33 events, input
  and output fields, `permissionDecision`, exit-code semantics, hook types
  (command, http, mcp_tool, prompt, agent), settings precedence.
- [Monitoring](https://code.claude.com/docs/en/monitoring-usage) — OTel metrics,
  `tool_decision` / `tool_result` events, MCP attribution, content gates
  (`OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_TOOL_CONTENT`, `OTEL_LOG_RAW_API_BODIES`),
  trace span hierarchy, managed-settings destination lockdown.
- [Sandboxing](https://code.claude.com/docs/en/sandboxing) — Seatbelt/bubblewrap,
  network proxy and domain allowlist, `strictAllowlist`,
  `allowManagedDomainsOnly`, credential `mask` with `injectHosts`,
  `network.tlsTerminate`, and the documented security limitations including domain
  fronting and Unix-socket escalation.
- [Security](https://code.claude.com/docs/en/security) — built-in prompt-injection
  safeguards, isolated WebFetch context, trust verification (and that it is
  disabled under `-p`), MCP security posture.
- [Permissions](https://code.claude.com/docs/en/permissions) and
  [managed settings](https://code.claude.com/docs/en/managed-settings) —
  evaluation order, `disableBypassPermissionsMode`, and that hook decisions do not
  bypass deny rules.

## Incidents

- **s1ngularity / nx** (26 August 2025) — **secondary**, corroborated across
  [Okta](https://www.okta.com/blog/threat-intelligence/the-s1ngularity-attack--when-attackers-prompt-your-ai-agents-to/),
  [Semgrep](https://semgrep.dev/blog/2025/security-alert-nx-compromised-to-steal-wallets-and-credentials/),
  [Endor Labs](https://www.endorlabs.com/learn/nx-build-platform-compromised-by-supply-chain-attack---how-attackers-collude-with-ai-code-assistants),
  and [Truesec](https://www.truesec.com/hub/blog/supply-chain-attack-on-popular-nx-package-suite).
  `telemetry.js` post-install; detection of Claude / Gemini / Amazon Q CLIs;
  `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`; exfiltration to
  public `s1ngularity-repository` repos. The specific GitGuardian figures (1,346
  repos, 2,349 secrets, 1,079 systems) from the originating brief were **not
  independently verified**; corroborating sources say "over two thousand distinct
  secrets."
- **GTG-1002** (disclosed 13 November 2025) — **secondary**, with Anthropic's own
  report available as a [PDF](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf).
  ~30 targets, 80–90% of operations executed by the AI, 4–6 human decision points,
  and task decomposition into instructions that appeared legitimate individually.

## MCP

- [Tool annotations as risk vocabulary](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
  — **secondary**. `readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`; that they are hints and clients should not trust them from an
  untrusted server.
- MCP specification revision 2025-11-25 — **secondary** (spec site egress-blocked).
- Tool poisoning / rug pull / shadowing taxonomy — **secondary**:
  [Speakeasy](https://www.speakeasy.com/resources/mcp-tool-poisoning/),
  [ByteTools](https://bytetools.io/guides/mcp-security),
  [Cloud Security Alliance research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/).
- [Parasites in the Toolchain](https://arxiv.org/pdf/2509.06572) — large-scale
  analysis of MCP ecosystem attacks. **Not read** (arxiv egress-blocked).

## Tooling

- [Snyk Agent Scan / mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) —
  **primary** for what the repo documents (scan mode, 14 risk indicators, Claude
  Code support, Apache-2.0, closed to contributions). Runtime proxy mode is
  **secondary/unverified**.
- MCP gateways — **secondary**:
  [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway),
  [open-source gateway survey](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026).

## Defensive architecture

- **CaMeL** — *Defeating Prompt Injections by Design*, arXiv:2503.18813.
  **Secondary** ([alphaXiv](https://www.alphaxiv.org/abs/2503.18813)); arxiv
  blocked. Dual-LLM (P-LLM / Q-LLM), custom interpreter with a dataflow graph,
  capability policies, 77% of AgentDojo with provable security.
- **Agents Rule of Two** — Meta, 31 October 2025. **Secondary** (ai.meta.com
  egress-blocked); corroborated by
  [Simon Willison](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
  and [Oso](https://www.osohq.com/learn/agents-rule-of-two-a-practical-approach-to-ai-agent-security).
- **AI control** — [Redwood Research](https://www.redwoodresearch.org/research/ai-control);
  [ControlArena](https://github.com/UKGovernmentBEIS/control-arena) (UK AISI with
  Redwood). **Secondary.**

## Benchmarks

- **SHADE-Arena** — Kutasov et al., arXiv:2506.15740. **Secondary.** Main task plus
  hidden side task, monitor blind to the side task.
- **AgentDojo** and the NIST CAISI result (11% baseline → 81% adapted attack success
  on Claude 3.5 Sonnet) — **secondary**, from the originating brief and search
  corroboration. Worth verifying directly at nist.gov; it is load-bearing for the
  "architecture over detection" argument.
- **Prompt Infection** — Lee & Tiwari, arXiv:2410.07283. **Secondary.**

## Standards

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
  (9 December 2025) — **secondary**. ASI01–ASI10 as listed in
  [06](06-prior-art.md).

## Not verified — do not rely on

Carried over from the originating research brief and listed in
[07](07-open-questions.md) Q10:

- OpenAI GPT-6 "Astra" system card (September 2026): CoT-monitor evasion, covert
  sandbagging, near-zero evasion against full-trajectory monitors.
- Claude Opus 4.6 Sabotage Risk Report (~18% / 16% side-task success under
  monitoring). Vendor-reported.
- Claude Fable 5.1 / Mythos 5.1 system card covert-evaluation results.
- The July 2026 OpenAI–Hugging Face multi-agent incident (~700 agents).
- MCP CVE counts (30+ Jan–Feb 2026) and the reported NSA/DoD MCP advisory
  (2 June 2026).

The design does not depend on any of these. It depends on the
action-monitoring-beats-reasoning-monitoring conclusion, which SHADE-Arena supports
on its own, and on the documented incidents above.
