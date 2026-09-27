# 04 — Data model

## Principles

1. **Digests by default, content by exception.** The default record carries hashes
   and extracted features, not payloads. Content is retained only where policy
   explicitly opts in, per action class.
2. **Redact at the endpoint.** Secret detection and stripping happen in `agentd`
   before anything leaves the machine. The fleet plane must never be the place a
   secret first lands.
3. **Append-only.** Events are immutable. Corrections are new events referencing
   the original. An audit trail that can be edited is not one.
4. **Correlation keys are first-class.** `session_id`, `prompt_id`, `tool_use_id`,
   `event.sequence` — these come from Claude Code and let us reconstruct order
   across both the hook stream and the OTel stream.

## Normalized event

One schema for every source (hooks, OTel, interposer), so detectors do not care
where a fact came from.

```jsonc
{
  "event_id":   "01JD...",          // ULID, sortable
  "ts":         "2026-09-27T11:50:03.412Z",
  "ingested_at":"2026-09-27T11:50:04.002Z", // for lag and gap detection
  "source":     "hook" | "otel" | "interpose" | "agentd",
  "schema_v":   1,

  "endpoint": {
    "endpoint_id": "ep_7f3a...",     // stable, enrollment-issued
    "hostname_digest": "sha256:...", // digest, not hostname
    "os": "darwin|linux|wsl2",
    "agentd_version": "0.3.1"
  },

  "actor": {
    "user_id": "u_1a2b",             // from OTel user.id / enrollment
    "org_id":  "o_9x8y"
  },

  "agent": {
    "kind": "claude-code",
    "version": "2.1.271",
    "entrypoint": "cli|sdk|ci|web",  // OTel app.entrypoint — key for D1
    "model": "claude-opus-5",
    "permission_mode": "default|plan|acceptEdits|auto|dontAsk|bypassPermissions",
    "cwd_digest": "sha256:...",
    "repo": { "remote_digest": "sha256:...", "branch": "main", "dirty": true },
    "sandbox": { "enabled": true, "strict_allowlist": true }
  },

  "session": {
    "session_id": "sess_...",
    "prompt_id":  "p_...",           // null before first user input
    "sequence":   1487,              // OTel event.sequence, per-process
    "agent_id": null,                // set inside a subagent
    "agent_type": null,
    "parent_session_id": null        // set for subagent subtrees
  },

  "kind": "session_start | prompt_submit | tool_pre | tool_post | tool_fail |
           permission_request | permission_denied | instructions_loaded |
           config_change | file_changed | mcp_list | subagent_start |
           subagent_stop | compact | session_end | agentd_health",

  "tool": {
    "name": "Bash",                  // or mcp__server__tool
    "use_id": "toolu_...",
    "mcp": { "server": "github", "tool": "create_issue",
             "annotations": { "readOnlyHint": false, "destructiveHint": false,
                              "openWorldHint": true },
             "metadata_hash": "sha256:..." },
    "bash": { "argv0": "curl", "command_class": "network",
              "command_digest": "sha256:...", "command": null },
    "paths": [ { "path_digest": "sha256:...", "zone": "workdir|home|credential|
                                                       untrusted|system",
                 "op": "read|write" } ],
    "input_digest":  "sha256:...",
    "input_features": { /* see Feature extraction */ },
    "result_digest": "sha256:...",
    "result_bytes": 18422,
    "content_ref": null              // blob ref, only if policy retains content
  },

  "provenance": {
    "taint": ["web:example.com", "mcp:github", "file:node_modules"],
    "ingest_refs": ["01JD...", "01JD..."],  // event_ids of the ingests
    "edges": [ { "from_event": "01JD...", "match_class": "domain",
                 "match_digest": "sha256:...", "confidence": 0.9 } ]
  },

  "r2": { "a": true, "b": true, "c": false, "set_by": "01JD..." },

  "policy": {
    "decision": "allow|deny|ask|allow_alert|fail_open",
    "reason": "R2-third-bit: egress after untrusted ingest and secret read",
    "rule_ids": ["r2.egress.deny", "prov.domain.match"],
    "bundle_version": "2026-09-20.3",
    "latency_us": 1840
  },

  "scores": {                        // async, attached by later events
    "goal_drift": null,
    "drift_scorer_v": null
  }
}
```

### Why digests for paths and hostnames

An event stream that carries every file path every agent reads across the company
is itself a map of the company's source tree, and the fleet plane is a target
([01](01-threat-model.md)). Digest by default; keep a salted local reverse map on
the endpoint so an investigator with cause can resolve a specific path, and
resolve centrally only for the small set of policy-relevant zone prefixes. This
costs investigation convenience and is worth it.

## Feature extraction

Computed at the edge from tool inputs and untrusted results. These are what
provenance matching runs on, and they are safe to ship where raw content is not.

```jsonc
{
  "domains":   ["sha256:...", ...],   // registrable domains, digested
  "urls":      ["sha256:...", ...],
  "emails":    ["sha256:...", ...],
  "ips":       ["sha256:...", ...],
  "hi_entropy":["sha256:...", ...],   // >=20 chars, entropy over threshold
  "shingles":  ["sha256:...", ...],   // rare n-grams only, corpus-filtered
  "secret_hits": [ { "kind": "aws_key", "count": 1 } ],  // kind only, never value
  "counts": { "bytes": 18422, "lines": 402 }
}
```

All fingerprints are **HMAC'd with a per-org key**, not plain SHA-256. Plain
hashes of short, low-entropy values (a domain, an email) are trivially brute-
forced, which would turn the event store into a confirmable list of every domain
and address the fleet ever touched. Keyed digests preserve the equality-matching
the provenance engine needs while removing offline dictionary attacks.

## Blob store

Content retained only under explicit policy. Content-addressed, encrypted with a
key the event store does not hold, with its own retention clock. Candidate
retention triggers: any event that produced a `deny`, any event carrying a
provenance edge above a confidence threshold, any MCP tool description that
changed, a sampled percentage for detector tuning.

Secrets are stripped before the blob is written, not after. A redaction pass that
runs on read is a redaction pass that will eventually be skipped.

## Retention

| Data | Default | Rationale |
| --- | --- | --- |
| Normalized events (digests, features) | 13 months | Incident lookback across a fiscal year |
| Blobs (retained content) | 30 days | Investigation window; longest-lived risk |
| Goal-drift scores | 13 months | Cheap, needed for baselining |
| MCP metadata baselines | indefinite | Drift detection needs the original |
| Endpoint reverse maps (path digests) | local only, 90 days | Never centralized |

These are starting numbers, not researched compliance positions. Whoever owns data
retention policy needs to review them before any deployment handling regulated
data — flagged in [07](07-open-questions.md).

## Volume estimate

Rough sizing to check the design is not absurd. Assume 63 active agents, a
moderately busy day of ~2,000 tool calls per agent, two events per call (pre and
post) plus overhead, ~1.5 KB per normalized event after compression:

- ~126k tool calls/day → ~300k events/day → **~450 MB/day**, ~13 GB/month.
- At 13-month retention: **~170 GB** of event data. Unremarkable for a columnar
  store.
- Blobs dominate if retention triggers are loose. A 60 KB content cap
  (Claude Code's OTel default) on even 2% of calls is ~150 MB/day. Triggers must
  stay narrow, and this is the number to watch.

The conclusion that matters: events are cheap and can be kept broadly; content is
expensive and sensitive and must be kept narrowly.

## Storage shape

- **Ingest**: append-only log (Kafka or equivalent), the durability boundary.
- **Analytics**: columnar store (ClickHouse or equivalent) for detector queries
  and baselining. Most detectors are windowed aggregations over one session or one
  endpoint.
- **Provenance**: the fingerprint intersection is per-session and lives in
  `agentd`'s memory during the session; only resulting edges are shipped.
  Cross-session matching (D10) runs centrally over the feature columns.
- **Graph**: not initially. The "graph" is narrow — ingest events to action events
  within a session — and joins over a columnar store handle it. Revisit only if
  multi-hop cross-session propagation analysis needs it.
