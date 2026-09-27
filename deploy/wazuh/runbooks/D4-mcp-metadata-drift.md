# Runbook D4 — MCP tool metadata drift

**Rules:** 100231–100240 (group `ambit_d4`). **MITRE:** T1195.002.

An MCP server advertises its tools to the agent: each tool's name, description and
input schema. The agent's model reads those descriptions and acts on them, so changing
a description changes what the agent does — no exploit required. This detector records
what each server advertised, compares it against a surface a human approved, and alerts
when the two differ.

You do not need access to the customer's source tree to work this alert. Server names
and tool names are in cleartext. Descriptions are not in the alert and are held on the
endpoint; step 4 says how to get them.

| Rule | Level | Means |
| --- | --- | --- |
| 100231 | 3 | Inventory record: one per server per session, with `mcp_tool_count` |
| 100232 | 5 | A tool nobody has seen before, recorded pending approval |
| 100233 | 7 | Metadata changed, but this server was never approved |
| 100234 | 12 | **Drift from an approved baseline** — the core D4 alert |
| 100235 | 10 | A previously approved tool is no longer advertised |
| 100236 | 13 | Drift on a tool the server itself marks destructive |
| 100237 | 13 | Drift that arrived mid-session, after the server announced a change |
| 100238 | 5 | The announcement itself, before any re-listing |
| 100239 | 8 | **Baseline unavailable** — drift could not be checked at all |
| 100240 | 12 | Three or more approved tools on one server drifted within 300s |

## What this alert asserts

For 100234, 100236, 100237 and 100240, all from fields in the alert:

- `tool_mcp_server` advertised a tool, `tool_mcp_tool`, whose metadata hash is
  `tool_mcp_metadata_hash`.
- A human previously approved that tool with hash `mcp_prev_metadata_hash`.
- The two differ, and `mcp_changed_fields` names which parts moved: `description`,
  `input_schema`, `name`, `title`, `output_schema` or `annotations`.
- `mcp_trigger` says how the listing arose: `tools_list` is routine session startup,
  `list_changed` means the server announced a change mid-session and the client
  re-listed.
- The hash covers name, description and input schema. `annotations` in
  `mcp_changed_fields` means a behavioral hint changed — for example a tool that
  claimed to be destructive no longer does — which is tracked separately from the hash.

For 100239: the endpoint could not read or write its baseline store, so **nothing was
compared on that endpoint**. Treat it as a gap in coverage, not as a clean result.

For 100232 and 100233: something changed, but no human had approved this server's
surface, so there is no reviewed state it deviated from.

## What it does not assert

- **It does not assert malice.** The overwhelmingly common cause is a legitimate server
  upgrade: a new version ships better descriptions, adds a parameter, or renames a tool.
  Expect a burst of 100234 across many endpoints within hours of a package release.
- **It does not assert the agent acted on the change.** Drift is detected when the
  server advertises, which happens at session start whether or not any tool is called.
- **It does not tell you what the description now says.** The text is not in the alert
  by design; see step 4.
- **100240's threshold is a placeholder.** Three tools in 300 seconds was set before
  fleet data existed. A server that renames its tools in a major release trips it
  legitimately.
- **100235 is not deletion.** A tool absent from a complete listing may be behind a
  feature flag, a permission change, or a downgrade.

## Triage

**Step 1 — routine upgrade, or not?** The discriminator is breadth and correlation:

- The same `tool_mcp_server` and the same `tool_mcp_metadata_hash` appearing across
  **many endpoints** in a short window is a version rollout. The hash is an unkeyed
  SHA-256 of the server's own advertised metadata, so it is directly comparable across
  endpoints, across customers, and against a copy of the package you install yourself.
  That is the fastest exoneration available and it needs nothing from us.
- The same server drifting on **one endpoint only**, while other endpoints running it
  report `approved`, is the serious case. One endpoint's copy of a shared server is
  advertising something the others are not.

**Step 2 — read `mcp_changed_fields`.** Ranked by how much each should worry you:

1. `description` alone — the tool does the same thing and describes it differently.
   This is the tool-poisoning vector: the description is the part the model obeys.
   Check for a companion D5 alert on the same `tool_name` (rules 100241–100247). If one
   is present, and especially if rule 100246 fired, stop treating this as an upgrade.
2. `input_schema` — a new or changed parameter. A new parameter that takes a URL,
   destination, path or token on a tool that previously took none is worth escalating
   even without a D5 hit.
3. `annotations` — a behavioral claim changed. `tool_mcp_destructive_hint` going from
   true to absent, or `tool_mcp_readonly_hint` appearing, is a server asserting it is
   safer than it was. These hints never relax policy in this system, but a server that
   starts claiming safety is asserting something about itself worth checking.
4. `name` — a rename. Usually a version change; occasionally a tool trying to occupy
   another tool's name, which pairs with a D5 `cross_server_ref` finding.

**Step 3 — check the timing.** `mcp_trigger` = `list_changed` (rule 100237) means the
server changed its surface *during* a session rather than at startup. A legitimate
server almost never does this; it happens on restart or upgrade, which normally means a
new session. Mid-session re-advertisement of changed metadata should be treated as
hostile until explained.

**Step 4 — correlate the session.** Pull other events with the same `endpoint_id` in
the surrounding hour:

- `kind` = `tool_pre` or `tool_post` with the same `tool_mcp_server` — was the drifted
  tool actually called after the drift was observed? `tool_name` on those events is the
  same `mcp__<server>__<tool>` string as on this alert, so they join directly.
- `policy_decision` other than empty, `r2_a`/`r2_b`/`r2_c`, `prov_edge_count` above
  zero on those calls — the drifted tool feeding an action that touched credentials or
  egress is the sequence that matters.
- `kind` = `config_change` or a FIM alert on `.mcp.json` in the same window means the
  server's *configuration* changed too, not only its advertised metadata. That is a
  different and worse story: it suggests something edited the endpoint, not the package.

**Step 5 — decide.** Escalate to us when any of: the drift is confined to one endpoint;
`mcp_changed_fields` contains `input_schema` with a new destination-shaped parameter;
rule 100236, 100237 or 100246 fired; the drifted tool was called and that call carries
a provenance edge or a non-empty `policy_decision`; or a FIM alert on `.mcp.json`
landed in the same window.

## What requires us

Three requests, all of which need the endpoint and cannot be served from the alert:

1. **Baseline pull** — the approved description and the drifted one, verbatim, for one
   `tool_mcp_server` and `tool_mcp_tool`. This is the single most useful artifact for
   this detector: it turns "the description changed" into the diff. Both versions are
   held on the endpoint in the baseline store, alongside the D5 rule ids that fired,
   which are deliberately not in the alert.
2. **Digest resolution** — any `*_digest` field in a correlated event. Zone labels are
   already in cleartext, so ask for resolution only when the specific path matters.
3. **Spool pull** — the full trajectory for an `endpoint_id` and time window, including
   the tool calls and results the flattened events summarize.

Request path and turnaround are set by the engagement, not by this document. If your
copy of this runbook does not name them, that is the gap to raise: an alert that cannot
be resolved is worse than no alert, because someone spent attention on it and got
nothing.

## Containment

**Nothing here is automatic and none of it is yours to execute.** Active response is
containment only and dispatch permission is not granted to external roles.

Recommend to us, in escalation order:

1. Remove the server from the affected endpoint's `.mcp.json`, or revoke its approval
   (`mcp-interpose -server <name> -revoke`) so every subsequent listing alerts.
2. Revoke credentials the server holds or could have reached, if the drifted tool was
   called.
3. Pin the package version fleet-wide and re-approve deliberately.

Do not recommend approving the new surface to clear the alert. Approval is the control
this detector compares against; clearing an unexplained alert by approving it is how
the control gets retired.

## Escalation

**Page** on rule 100236, 100237 or 100246; on 100234 confined to a single endpoint; or
on 100234 correlated with a FIM alert on `.mcp.json` in the same window.

**Queue** 100234 that matches a fleet-wide rollout, 100233, 100235 and 100240.

**Batch and report** 100231, 100232 and 100238 in the periodic summary; they are
inventory, and M1's own exit criterion is that the inventory exists and is approved.

**100239 is an availability escalation, not a security one**, and it does not wait for a
threshold: raise it to us the same day. An endpoint that cannot compare baselines is an
endpoint where D4 is switched off, and the alert stream from it will look calm.
