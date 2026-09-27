# Runbook D9 — egress anomaly

**Rules:** 100300–100303 (group `ambit_d9`). **MITRE:** T1041, T1567, T1552.

Exfiltration needs an outbound path, and a coding agent has several legitimately: git push,
package installs, API calls. This detector reports the shape of outbound activity rather than
claiming to identify exfiltration, because the volume-and-destination profiling the catalogue
describes is not something a rule can do.

| Rule | Level | Means |
| --- | --- | --- |
| 100300 | 5 | A network-capable command (context) |
| 100301 | 12 | 10+ network-capable commands in one session within 300s |
| 100302 | 13 | **Secret material in a network-capable command** |
| 100303 | 10 | Result from an open-world MCP tool — **inert, see below** |

## What this alert asserts

- `bash_command_class` is `network`: the endpoint classified the command's argv0 as
  network-capable — `curl`, `wget`, `nc`, `ssh`, `scp`, a push, a publish. `bash_argv0` names it.
  The command text itself is a keyed digest and does not cross.
- For 100302: the same event also carries `secret_hit_kinds`, meaning the edge classifier
  recognized credential material **in the command line**. The kind is named; the value is
  stripped at the edge and exists in no event.
- For 100301: ten or more such commands inside five minutes in one session.

## What it does not assert

- **No destination, no volume.** The flattened event carries neither the URL nor the byte count.
  Profiling "outside this endpoint's normal destinations" needs a per-endpoint baseline, which is
  a scheduled query over the indexer or the spool, and it is not built. Do not read 100301 as
  "unusual for this endpoint" — read it as "a rate that is hard to produce by hand".
- **Sandbox denials are not here at all.** The catalogue lists "any sandbox allowlist denial" as
  a D9 signal. Claude Code's sandbox denies outbound connections, and ambit has no schema field
  to carry that — not an unpopulated field, an absent one. Adding it is an M2 schema change. So a
  *blocked* exfiltration attempt does not appear in this detector today.
- **Rule 100303 is inert.** An open-world MCP tool's result should be treated as untrusted
  ingest, and the annotation that says so is known to the interposer — but it is not carried on
  tool *call* events, because those come from the hook path and a hook payload contains no
  annotations. The join lands with M2; until then this rule cannot fire and is marked
  `ambit_pending_emitter`.
- **A command's file paths are not attached.** `cat ~/.aws/credentials | curl ...` produces a
  network-class event with no credential path, because paths come from a tool's structured input
  rather than from parsing a shell pipeline. The correlation that catches it is the R2 accounting
  and the provenance edges, both M2.

## Triage

1. **For 100302, start containment while you triage.** Credential material on a command line
  going outbound is the strongest single-event signal in this detector, and `secret_hit_kinds`
  names what kind. Rotate first, explain second.
2. **For 100301, read `bash_argv0` across the burst.** Ten `git` invocations during a rebase is
   ordinary. Ten `curl` calls in five minutes is a loop, and a loop is either a script or a
   download.
3. **Check the session's ingest side.** Same `session_id`: a D8 untrusted instruction file, a D4
   drift, or a `tool_post` carrying `prov_fp_notable` before the egress tells you the session had
   ingested untrusted content first. Egress after ingest is the shape the whole system exists to
   catch; egress alone, in a session doing ordinary work, usually is not.
4. **Check for credential reads before the egress.** A D2 alert or a `path_zone` = `credential`
   read in the same session, followed by network commands, is the staging-then-exfiltration
   sequence even without the sandbox denial or the destination.
5. **Ask whether the endpoint is a build machine.** Most 100301 volume will come from a handful of
   endpoints that legitimately talk to the network constantly.

## What requires us

- **The command text**, resolved from its digest. For this detector it is the artifact that
  resolves almost every alert: the destination is in the command line and nowhere else.
- **Spool pull** for the session, to establish order: ingest, then credential access, then egress.
- **The endpoint's role** — developer laptop or CI runner.
- **Whether the sandbox blocked it.** Not in the event stream; it may be in Claude Code's own
  logs on the endpoint.

## Containment

1. For 100302: revoke the credential kind named in the alert, immediately, before analysis
   finishes. This is the one alert in this detector where waiting costs more than acting.
2. For a confirmed exfiltration destination, ask us to add it to the egress denylist and to check
   whether the managed egress allowlist should have blocked it — a D12 failure on SCA check 10004
   would say it was supposed to.
3. For 100301 with a plausible build explanation, no containment; give us the endpoint so the
   threshold can be set from its real rate.

## Escalation

**Page** on 100302, and on 100301 correlated with credential access or an untrusted ingest in the
same session.

**Queue** 100301 alone.

**Do not page** 100300; it is level 5 because it is ordinary developer traffic and exists to give
the egress timeline during triage.
