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

## Wazuh

`documentation.wazuh.com` is blocked by this environment's egress proxy, so everything
below was verified against the **documentation source and shipped ruleset on GitHub**,
pinned to **v4.14.1** unless noted. That is the same text the site renders, so these
count as primary — but they are version-pinned, and see Q12 on the 5.0 engine rewrite.

**Primary — rule syntax**
([`ruleset-xml-syntax/rules.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/ruleset/ruleset-xml-syntax/rules.rst)):
rule `id` 1–999999 with custom rules conventionally above 100000; `level` 0–16;
`frequency` 2–9999, triggering at that many matches or more within the timeframe;
`timeframe` 1–99999 seconds; `if_sid`, `if_matched_sid`, `if_group`, `if_matched_group`;
`field name=`; `<mitre>`; `group`; `description`. And on `same_field`: "The value of the
dynamic field specified in this option must appear a certain number of times in previous
events, as defined by the `frequency` attribute, within a time frame specified by the
`timeframe` attribute," with the note that `same_field` "will not work with the static
fields ... and the specific ones have to be used instead."

**Primary — `same_field` in practice**
([`ruleset/rules/`](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/ruleset/rules/),
0350-amazon_rules.xml, 0580-win-security_rules.xml): rule 80443
(`frequency="8" timeframe="120" ignore="60"`, `if_matched_sid`, `same_field`
`aws.httpRequest.clientIp`) and rules 60203/60204 confirm the pattern D2, D10's tripwire
and D11 use, and confirm nested JSON fields are addressed with dot notation.

**Primary — agent disconnection**
([`0015-ossec_rules.xml`](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.1/ruleset/rules/0015-ossec_rules.xml)):
rule **504**, level 3, `Wazuh agent disconnected`, `<mitre><id>T1562.001</id></mitre>`.
This is D7's coarse half, free.

**Primary — JSON decoder**
([`decoders/json-decoder.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/ruleset/decoders/json-decoder.rst)):
extracts numbers, strings, booleans, nulls, objects, and arrays — "Lists with zero or
more values ... **An array of objects is not supported.**" Extracted fields are stored
as dynamic fields referable from rules. **This is the constraint that forces the
flattened schema**, not nesting depth.

**Primary — field limit**
([`reference/internal-options.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/reference/internal-options.rst)):
`analysisd.decoder_order_size`, "Maximum number of fields in a decoder (order tag),"
default **256**, allowed 32–1024, overridable via `local_internal_options.conf`.

**Secondary/unverified — the JSON coupling:** the documented description is in terms of
the `order` tag, while the `wazuh-analysisd: ERROR: Too many fields for JSON decoder`
error is attributed to this same setting by users and community write-ups
([wazuh/wazuh#24734](https://github.com/wazuh/wazuh/issues/24734),
[#6325](https://github.com/wazuh/wazuh/issues/6325)). The reported remedy is raising it
to 1024. Treat the exact coupling as unconfirmed; the operational hazard — a wide event
being rejected, which is silent detection loss — is what the design responds to.

**Primary — archiving**
([`reference/ossec-conf/global.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/reference/ossec-conf/global.rst)):
`logall` writes all events to `archives.log` and `logall_json` to `archives.json`, both
"even when they do not trip a rule"; both default `no`. Also
`agents_disconnection_time` and `agents_disconnection_alert_time` (default `0s`; with
default values the documented minimum time to produce an alert is 2m20s).

**Primary — log collection**
([`reference/ossec-conf/localfile.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/reference/ossec-conf/localfile.rst)):
`log_format json` is "used for single-line JSON files and allows for customized labels
to be added to JSON events"; `label` supports dot notation; `only-future-events`, `age`,
`ignore`, `out_format`, `target`. Multi-line JSON is not supported.

**Primary — FIM**
([`reference/ossec-conf/syscheck.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/reference/ossec-conf/syscheck.rst)):
`directories` with `realtime`, `whodata`, `check_all`, `report_changes`,
`recursion_level`, `restrict`, `tags`. Two facts the design depends on: **"Real time
only works with directories, not individual files"** — hence watching `.claude/` with
`restrict` rather than naming `settings.json` — and `whodata` reports the user and
process responsible via Linux Audit or eBPF, which `realtime` does not.
`report_changes` is text-only, bounded by `diff_size_limit` (default 50 MB).

**Primary — SCA**
([`capabilities/sec-config-assessment/`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/capabilities/sec-config-assessment/creating-custom-policies.rst)):
YAML policies with `policy`, optional `requirements`, and `checks` blocks. Rule prefixes
`f:` file, `d:` directory, `p:` process, `c:` command output, `r:` Windows registry.
Content matching with `->`, regex via `r:`, numeric comparison via `n:...compare`,
chaining with `&&`, negation with `not`. Per-check `condition` of `all` / `any` / `none`.
`regex_type` selects `osregex` (default) or `pcre2`. Custom policies are supported
("you can also write your own policies or extend existing ones").

**Thin — active response**
([`capabilities/active-response/index.rst`](https://raw.githubusercontent.com/wazuh/wazuh-documentation/v4.14.1/source/user-manual/capabilities/active-response/index.rst)):
triggered by rule ID, level, or group; stateless and stateful responses; the index page
warns that "poor implementation of rules and responses might increase the vulnerability
of an endpoint." The `location` values and `timeout_allowed` were **not** read from the
how-to-configure page — **unverified** at that level of detail.

**Unverified — how a `<field>` regex matches a multi-valued field.** The JSON decoder
documentation states arrays of scalars are supported ("lists with zero or more values"),
but not whether a rule's `<field>` pattern is tested against each value or against one
joined string. Two of the shipped D4/D5 fields are arrays (`mcp_changed_fields`,
`mcp_scan_classes`). The rules in `deploy/wazuh/rules/ambit_mcp_rules.xml` therefore
match array contents with **unanchored literals**, which work under either behavior, and
`deploy/wazuh/rules_test.go` fails the build if a pattern on an array field is anchored.
Confirm with `wazuh-logtest` against the committed fixtures before relying on rules
100241–100247.

**Unverified — SCA alert rule IDs.** The parent SID and `sca.*` field names used in
[03](03-detection.md)'s D12 rule were not checked against the shipped SCA ruleset. That
snippet is the intended shape, not working configuration.

**Secondary — multi-tenancy.** Wazuh is not natively multi-tenant the way commercial
SIEMs are; the practical patterns are manager-per-tenant or agent groups plus RBAC plus
index-level restrictions, and when multiple managers feed one indexer some internal
metadata is shared rather than tenant-scoped. All community sources
([Wazuh RBAC](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)
is the product doc for the RBAC half; the tenancy patterns are blog and mailing-list
material). Basis for [07](07-open-questions.md) Q11.

**Secondary — Wazuh 5.0 engine.** 5.0 migrates decoders and rules from XML to YAML with
an ECS-normalized common schema, per Wazuh's own migration issues
([wazuh/wazuh#8004](https://github.com/wazuh/wazuh/issues/8004),
[#7914](https://github.com/wazuh/wazuh/issues/7914),
[#8011](https://github.com/wazuh/wazuh/issues/8011)). Corroborating signal: the
main-branch `internal-options.rst` no longer lists `analysisd.decoder_order_size`. Not
verified against a 5.0 release note. Basis for [07](07-open-questions.md) Q12.

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
