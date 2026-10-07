# 04 — Data model

Two representations, deliberately. A **rich internal event** that `ambitd` computes
and stores locally, and a **flattened SIEM-bound event** that crosses to Wazuh. The
mapping between them is documented below and is part of the contract.

## Principles

1. **Digests by default, content by exception.** The default record carries hashes
   and extracted features, not payloads.
2. **Zone labels in cleartext, paths as keyed digests.** An external analyst needs to
   know a read hit a credential path; they do not need our directory names
   ([01](01-threat-model.md)).
3. **Redact at the endpoint.** Secret detection and stripping happen in `ambitd`
   before anything is written to `events.jsonl`.
4. **Filter at the endpoint.** Wazuh gets security-relevant events; the full
   trajectory stays local. See [what crosses](#what-crosses-to-wazuh).
5. **Append-only.** Events are immutable; corrections are new events referencing the
   original.
6. **Correlation keys are first-class.** `session_id`, `prompt_id`, `tool_use_id`,
   `sequence` — from Claude Code, letting us reconstruct order across both streams.

## Why the SIEM-bound event is flattened

The constraint is not nesting depth. Wazuh's JSON decoder stores extracted keys as
**dynamic fields** addressable with dot notation, and the shipped ruleset does
exactly this at three levels (`aws.httpRequest.clientIp`,
`win.eventdata.targetUserName`). Nested objects are fine.

Two real constraints drive the flattening:

1. **"An array of objects is not supported."** Stated outright in the JSON decoder
   documentation. Arrays of *scalars* are supported ("lists with zero or more
   values"); arrays of *objects* are not. Our internal schema is full of them —
   `tool.paths[]`, `provenance.edges[]`, `input_features.secret_hits[]`. These
   cannot be represented in a Wazuh-bound event at all, in any nesting arrangement.
   They must be collapsed to scalars or fanned out into separate events.
2. **Field count.** `analysisd.decoder_order_size` defaults to **256** with an
   allowed range of 32–1024, documented as "maximum number of fields in a decoder
   (order tag)," overridable via `local_internal_options.conf`. Community reports
   attribute the `wazuh-analysisd: ERROR: Too many fields for JSON decoder` error to
   this limit *(the documentation describes the setting in terms of the `order` tag,
   so the exact coupling to the JSON decoder is **secondary/unverified**)*. Either
   way, a wide event is a real operational hazard — the reported failure mode is the
   manager rejecting events, which means silent detection loss.

So: keep the rich schema internally, and emit a flat, scalar-only, narrow event to
Wazuh. Target **under 40 fields** per SIEM-bound event, comfortably inside even the
32-field floor of the range for the fields any single rule needs.

## Internal event (rich, local only)

Unchanged in shape from the pre-Wazuh design; this is what `ambitd` computes and
spools.

```jsonc
{
  "event_id": "01JD...", "ts": "...", "ingested_at": "...",
  "source": "hook|otel|interpose|ambitd", "schema_v": 2,

  "endpoint": { "endpoint_id": "ep_7f3a...", "hostname_digest": "...",
                "os": "darwin|linux|windows", "ambitd_version": "0.3.1" },
  "actor":    { "user_id": "u_1a2b", "org_id": "o_9x8y" },
  "agent":    { "kind": "claude-code", "version": "2.1.271",
                "entrypoint": "cli|sdk|ci|web", "model": "...",
                "permission_mode": "...", "cwd_digest": "...",
                "repo": { "remote_digest": "...", "branch": "main", "dirty": true },
                "sandbox": { "enabled": true, "strict_allowlist": true } },
  "session":  { "session_id": "...", "prompt_id": "...", "sequence": 1487,
                "agent_id": null, "agent_type": null, "parent_session_id": null },

  "kind": "session_start | prompt_submit | tool_pre | tool_post | tool_fail | ...",

  "tool": {
    "name": "Bash", "use_id": "toolu_...",
    "mcp": { "server": "github", "tool": "create_issue",
             "annotations": { "readOnlyHint": false, "openWorldHint": true },
             "metadata_hash": "..." },
    "bash": { "argv0": "curl", "command_class": "network", "command_digest": "..." },
    "paths": [ { "path_digest": "...", "zone": "credential", "op": "read" } ],
    "input_digest": "...", "result_digest": "...", "result_bytes": 18422,
    "input_features": { "domains": [...], "urls": [...], "emails": [...],
                        "ips": [...], "hi_entropy": [...], "shingles": [...],
                        "secret_hits": [ { "kind": "aws_key", "count": 1 } ] },
    "content_ref": null
  },

  "provenance": {
    "taint": ["web:...", "mcp:github"],
    "ingest_refs": ["01JD...", "01JD..."],
    "edges": [ { "from_event": "01JD...", "match_class": "domain",
                 "match_digest": "...", "confidence": 0.9 } ]
  },

  "r2": { "a": true, "b": true, "c": false, "set_by": "01JD..." },
  "policy": { "decision": "deny", "reason": "...", "rule_ids": [...],
              "bundle_version": "...", "latency_us": 1840 },
  "scores": { "goal_drift": null, "drift_scorer_v": null }
}
```

## SIEM-bound event (flat, one JSON object per line)

Snake_case, scalar values only, no arrays of objects, no nesting beyond what a
`label` adds.

```jsonc
{
  "schema_v": 2,
  "event_id": "01JD...",
  "ts": "2026-09-27T11:50:03.412Z",
  "src": "hook",
  "kind": "tool_pre",

  "endpoint_id": "ep_7f3a...",
  "os": "darwin",
  "ambitd_version": "0.3.1",
  "user_id": "u_1a2b",
  "org_id": "o_9x8y",

  "agent_kind": "claude-code",
  "agent_version": "2.1.271",
  "agent_entrypoint": "cli",
  "agent_model": "claude-opus-5",
  "permission_mode": "bypassPermissions",
  "sandbox_enabled": true,
  "sandbox_strict_allowlist": true,
  "repo_remote_digest": "hmac:...",
  "repo_branch": "main",

  "session_id": "sess_...",
  "prompt_id": "p_...",
  "sequence": 1487,
  "subagent_type": null,
  "parent_session_id": null,

  "tool_name": "Bash",
  "tool_use_id": "toolu_...",
  "tool_mcp_server": null,
  "tool_mcp_tool": null,
  "tool_mcp_readonly_hint": null,
  "tool_mcp_destructive_hint": null,
  "tool_mcp_openworld_hint": null,
  "tool_mcp_metadata_hash": null,
  "bash_argv0": "curl",
  "bash_command_class": "network",

  "path_zone": "credential",
  "path_op": "read",
  "path_digest": "hmac:...",
  "path_count": 1,

  "secret_hit_kinds": ["aws_key"],
  "result_bytes": 18422,

  "taint_labels": ["web:hmac:...", "mcp:github"],
  "prov_edge_count": 1,
  "prov_edge_class": "domain",
  "prov_edge_confidence": 0.9,
  "prov_edge_from": "01JD...",
  "prov_fp_notable": "hmac:...",
  "prov_fp_role": "output",

  "r2_a": true,
  "r2_b": true,
  "r2_c": false,

  "policy_decision": "deny",
  "policy_reason": "R2-third-bit: egress after untrusted ingest and secret read",
  "policy_rule_id": "r2.egress.deny",
  "policy_bundle_version": "2026-09-20.3",

  "goal_drift_score": null
}
```

`taint_labels` and `secret_hit_kinds` are arrays of **strings**, which the decoder
supports.

**Measured field counts** (from `internal/event` tests, which fail the build if these
regress): **49 for a Bash tool event, 50 for an MCP tool event** — the two widest —
and 25–31 for `session_start`, `config_change` and `ambitd_health`. An earlier draft
of this document estimated 37; that was wrong, and it was wrong in the direction of
under-counting. The real ceiling matters less than it looked, though: 50 is far under
the 256 default for `decoder_order_size`, so the budget enforced in tests is 55 with a
70-field ceiling on the synthetic union of every optional block.

Two things keep the count honest. A single event never carries the tool, config and
health blocks together, and a tool event never carries both the MCP and Bash blocks —
measuring their union describes an event that cannot exist. And session-constant
fields (`agent_*`, `repo_*`, `sandbox_*`) are **deliberately repeated on every event**
rather than emitted once on `session_start` and joined: a Wazuh rule can only test
fields present on the event it is evaluating, so D1 needs `agent_entrypoint` and
`permission_mode` on the tool event itself. Denormalization is the correct trade for a
SIEM.

## Mapping, and where it loses information

| Internal | Flattened | Transformation | Loss |
| --- | --- | --- | --- |
| `endpoint.*`, `actor.*` | `endpoint_id`, `os`, `ambitd_version`, `user_id`, `org_id` | prefix-collapse | none |
| `agent.repo.{remote_digest,branch}` | `repo_remote_digest`, `repo_branch` | prefix-collapse | `dirty` dropped |
| `tool.mcp.annotations.readOnlyHint` | `tool_mcp_readonly_hint` | prefix-collapse | none |
| `tool.paths[]` | `path_zone`, `path_op`, `path_digest`, `path_count` | **array of objects → scalars** | **Only the highest-severity path survives**, ranked `credential` > `system` > `untrusted` > `home` > `workdir`. `path_count` preserves the cardinality D2 needs. Multi-path calls lose their other paths to the SIEM; the full list stays in the internal event. |
| `tool.input_features.secret_hits[]` | `secret_hit_kinds` | objects → array of kind strings | per-kind counts dropped |
| `tool.input_features.{domains,urls,...}` | **not emitted** | — | **Deliberate.** Hundreds of fingerprints per event is the firehose. `ambitd` intersects locally; only `prov_edge_*` and `prov_fp_notable` cross. |
| `provenance.edges[]` | `prov_edge_count` + highest-confidence edge as `prov_edge_{class,confidence,from}` | **array of objects → scalars** | Additional edges lost to the SIEM; count preserved |
| `provenance.ingest_refs[]` | **not emitted** | — | Resolvable from the spool on request |
| `provenance.taint[]` | `taint_labels` | array of strings, supported as-is | none |
| `r2.{a,b,c}` | `r2_a`, `r2_b`, `r2_c` | prefix-collapse | `set_by` dropped |
| `policy.rule_ids[]` | `policy_rule_id` | first / highest-precedence rule | Additional rule IDs lost; the deciding rule is the one that matters for triage |
| `policy.latency_us` | **not emitted** | — | Operational metric, not security signal; stays local |

**The recurring loss is "array of objects → the one that matters most, plus a
count."** That is an acceptable trade for a SIEM-bound event and an unacceptable one
for forensics, which is why the internal event keeps everything and the spool is
pullable. Any runbook step that needs a second path or a second edge is a
[digest-resolution / spool-pull request](03-detection.md#runbooks), by design.

## What crosses to Wazuh

Wazuh is a SIEM, not an analytics warehouse. The volume estimate below is ~300k
events/day for 63 agents; pushing all of it in — and especially enabling
`logall_json`, which writes *every* event including ones that trip no rule to
`archives.json` — turns the indexer into an expensive, slow copy of a log file.

**`logall` and `logall_json` stay `no`.** Both default to `no`; leave them there.
Archiving is what the local spool and object storage are for.

Filtering happens in `ambitd`, by event kind:

| Event kind | Crosses to Wazuh? | Rationale |
| --- | --- | --- |
| `session_start` | **yes** | Session provenance; D1 needs `entrypoint` and `permission_mode` |
| `session_end` | **yes** | Session closure, for windowed queries |
| `prompt_submit` | **metadata only** — no prompt text | Presence/absence is D1's core signal; the text is sensitive and not needed for a rule |
| `tool_pre` | **only when interesting** (below) | The firehose lives here |
| `tool_post` | **only when interesting** | Same |
| `tool_fail` | **yes** | Blocked-attempt signal, low volume |
| `permission_denied` | **yes** | Attack-attempt signal, low volume |
| `instructions_loaded` | **yes** | D8; low volume |
| `config_change` | **yes** | D6; low volume |
| `mcp_list` | **yes** | D4, D5; once per server per session |
| `subagent_start` / `subagent_stop` | **yes** | Low volume, needed for provenance scoping |
| `compact` | **yes** | Low volume; needed to interpret R2 state ([07](07-open-questions.md) Q1) |
| `ambitd_health` | **yes** | D7, D11 |
| `goal_drift_score` | **only above threshold** | One score per tool call is the firehose again |

A `tool_pre` or `tool_post` event is **interesting** — and therefore crosses — when
any of:

- `policy_decision` is not `allow` (`deny`, `ask`, `allow_alert`, `fail_open`)
- `prov_edge_count > 0`
- the event sets an R2 bit (transition, not steady state)
- `path_zone` is `credential` or `system`
- `secret_hit_kinds` is non-empty
- `bash_command_class` is `network`
- `tool_mcp_destructive_hint` is true, or the MCP server is not `internal`
- `prov_fp_notable` is present (D10's scalar tripwire)
- it falls in a **sampled remainder**, at a low rate (start 0.5%), so the SIEM holds
  enough ordinary traffic to baseline against

Everything else — the overwhelming majority: reading source files in the working
directory, ordinary edits, allowed local commands — stays in the local spool.

### Estimated reduction

Of ~126k tool calls/day across 63 agents, a plausible interesting fraction is
2–5%: credential and system reads, network commands, MCP calls, and anything with a
verdict or an edge. With the low-volume kinds added and 0.5% sampling of the
remainder:

- **~8–15k events/day to Wazuh** rather than ~300k. Roughly a **20–40× reduction**.
- At ~1.5 KB/event that is **~12–22 MB/day** indexed, ~400–700 MB/month. Unremarkable
  for a Wazuh indexer.
- The full ~300k events/day (~450 MB/day) stays local, spooled and rotated.

These ratios are estimates from the interesting-criteria above, not measurements.
**Measuring the actual interesting fraction is an M0 exit criterion** — if it comes
back at 30% rather than 3%, the criteria tighten or the sampling drops, before M1.

## Feature extraction

Computed at the edge from tool inputs and untrusted results. Feeds the local
provenance intersection; **only derived edges and the single notable fingerprint
cross to Wazuh.**

```jsonc
{
  "domains": [...], "urls": [...], "emails": [...], "ips": [...],
  "hi_entropy": [...], "shingles": [...],
  "secret_hits": [ { "kind": "aws_key", "count": 1 } ],
  "counts": { "bytes": 18422, "lines": 402 }
}
```

All fingerprints are **HMAC'd with a per-org key**, not plain SHA-256. Plain hashes
of short, low-entropy values (a domain, an email) are trivially brute-forced, which
would turn the event store into a confirmable list of every domain and address the
fleet ever touched — and with an MSSP holding a copy, that list leaves our control.
Keyed digests preserve the equality-matching provenance needs while removing offline
dictionary attacks.

The HMAC key is **ours and is not shared with the MSSP.** They can see that two
events carry the same digest — which is what D10's tripwire needs — without being
able to learn what it is.

## Retention, split

| Data | Where | Default | Rationale |
| --- | --- | --- | --- |
| SIEM-bound alerts and events | **Wazuh indexer** | 13 months | Incident lookback across a fiscal year; the volume above makes this cheap |
| Wazuh `archives.json` | **disabled** | — | `logall_json` stays `no` |
| Full trajectory (all events, rich schema) | **local spool → object storage** | 90 days | The investigation corpus. Cheap storage, not indexed. |
| Retained content blobs | **local / object storage, encrypted** | 30 days | Highest-sensitivity, shortest clock |
| Goal-drift scores (all) | **local spool** | 90 days | Only above-threshold scores reach Wazuh |
| MCP metadata baselines | **local + Wazuh** | indefinite | Drift detection needs the original |
| Endpoint path-digest reverse maps | **endpoint only** | 90 days | Never centralized, never sent to the MSSP |

Two things follow from this split. First, Wazuh's retention is a *detection* window,
not an archive — the archive is object storage, and it is where any
digest-resolution or spool-pull request is served from. Second, the MSSP sees the
Wazuh copy only, which is the 13-month digest-bearing event and alert stream, and
never the trajectory spool, the blobs, or the reverse maps.

These numbers are starting points, not researched compliance positions. Whoever owns
data retention needs to review them before any deployment handling regulated data,
and the MSSP contract has to match ([07](07-open-questions.md) Q3).

## Volume estimate

Assume 63 active agents, ~2,000 tool calls per agent per day, two events per call
plus overhead, ~1.5 KB per event compressed:

| | Events/day | Bytes/day | 13 months |
| --- | --- | --- | --- |
| Total generated | ~300k | ~450 MB | ~170 GB |
| **To Wazuh** | ~8–15k | ~12–22 MB | **~5–9 GB** |
| To local spool / object storage | ~300k | ~450 MB | ~40 GB at 90 days |

Blobs dominate if retention triggers are loose. A 60 KB content cap on even 2% of
calls is ~150 MB/day. Triggers stay narrow, and this is the number to watch.

The conclusion that matters: **events are cheap and belong broadly in cheap storage;
alerts and security-relevant events belong in the SIEM; content is expensive and
sensitive and belongs narrowly and briefly.**

## Storage shape

- **SIEM**: Wazuh manager → indexer. Detector rules are windowed correlations over
  one session or one endpoint, which `frequency` + `timeframe` + `same_field` handles
  natively ([03](03-detection.md)).
- **Spool**: `events.jsonl` rotated locally with a bounded disk cap, shipped
  periodically to object storage. Not indexed; queried by pull during investigation.
- **Provenance**: fingerprint intersection is per-session, in `ambitd`'s memory
  during the session. Only edges and the notable fingerprint are emitted.
  Cross-session set matching (D10's real form) runs as a scheduled job over object
  storage or the indexer's feature columns.
- **Graph store**: still not needed. The graph is narrow — ingest events to action
  events within a session — and the intersection is in memory anyway. Revisit only if
  multi-hop cross-session propagation analysis becomes a requirement.
