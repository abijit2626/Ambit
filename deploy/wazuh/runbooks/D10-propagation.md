# Runbook D10 — cross-agent fingerprint propagation

**Rules:** 100280–100283 (group `ambit_d10`). **MITRE:** T1105, T1570.

If an injection reaches one agent and that agent's output reaches another — through a shared
wiki, a ticket, a commit message, an MCP tool result — the injection propagates. This detector
looks for the same distinctive content appearing in two places it should not have.

**Read this first: the rules here are a tripwire, not the detector.** The real question is
whether the set of fingerprints one agent ingested intersects the set another later emitted, and
a Wazuh rule cannot express a set intersection. So ambitd pre-selects at most one
high-specificity fingerprint per event as a scalar, and these rules correlate on that. The full
intersection is a scheduled job over the feature columns and lands in M5.

| Rule | Level | Means |
| --- | --- | --- |
| 100280 | 0 | An event carries a notable fingerprint (context only, no alert) |
| 100281 | 10 | The same fingerprint seen **twice** within 3600s |
| 100282 | 12 | The same fingerprint seen **5+ times** within 7200s |
| 100283 | 12 | A provenance edge: the action carried a value that untrusted content introduced earlier in the same session |

## What this alert asserts

- The same value of `prov_fp_notable` appeared on two or more events inside the window.
- `prov_fp_notable` is a **keyed digest** of one high-specificity feature — a domain, an email
  address, or a high-entropy token — selected from the content of a tool result or input. Equality
  is all an analyst gets: two events saw the same thing. What that thing was requires resolution.
- `prov_fp_role` says whether the fingerprint was seen on the ingest or the output side of the
  event that carried it.

## What it does not assert

Three limitations, all structural rather than tuning problems, and all worth stating before you
spend time on an alert:

- **It does not assert two different sessions.** `same_field` takes one field name, and whether it
  composes with a test for a *differing* session id is unverified. So 100281 fires just as
  readily when one session ingests a fingerprint and later re-emits it — which is ordinary
  behavior, not propagation. **Checking whether the correlated events share a `session_id` is
  therefore triage step 1, not an afterthought.**
- **It does not assert direction.** D10 means "ingested in X, emitted by Y". The rule sees two
  occurrences of a value and cannot order them. `prov_fp_role` carries direction per event, so
  you can recover it by reading the events; the rule cannot require it.
- **It does not assert the content was malicious.** A shared internal domain appearing in two
  agents' tool results is what a company wiki looks like. This detector's false-positive rate is
  expected to be high, which is why 100281 is level 10 and not 12, and why the scalar tripwire
  exists only because it is nearly free.
- **Rule 100283 is live, and is evidence, not proof.** A provenance edge is ambitd's own
  statement that an action carried a value which also appeared in untrusted content it ingested
  earlier in the same session — the signal this tripwire approximates. It cannot say the value
  was *copied* from there: the user may have supplied it too (a value the user typed in a
  prompt is excluded, but one typed after the ingest is not), and the model may have
  reconstructed it. A paraphrase defeats it entirely, so a quiet 100283 means little.
  `prov_edge_confidence` ranks the match: 0.95 a full URL or a checksum-valid IBAN
  (`prov_edge_class` = `iban`: an account number from the earlier content appears in this action,
  which is either a payment to it or the account itself being sent somewhere), 0.90 an email or
  opaque token, 0.80 a bare domain, 0.40 a domain the operator trusts for content. Only the strongest edge and the
  count cross; the edges and the ingest event they point at are in the local spool, resolvable
  on request via `prov_edge_from`.

## Triage

1. **Same session or different?** Pull both correlated events by `prov_fp_notable`. Same
   `session_id` — close it, that is one agent handling the same content twice. Different
   `session_id`, and especially different `endpoint_id`, is the case worth working.
2. **Read the roles.** `prov_fp_role` = `ingest` on the earlier event and `output` on the later
   one, in different sessions, is propagation in the direction D10 means. The reverse ordering, or
   two ingests, is two agents reading the same source — which is normal.
3. **Count the endpoints.** One fingerprint across five sessions on five endpoints (rule 100282)
   is either a widely shared internal resource or something spreading. The distinction is what the
   fingerprint resolves to.
4. **Resolve the fingerprint.** Until you know whether it is the company wiki domain or an
   attacker's host, nothing else is decidable. This requires us and it is the whole alert.
5. **Check the ingest side for a known-bad origin.** If the earliest event carrying the
   fingerprint also has a D8 or D4 alert in its session, you have a candidate origin and the
   propagation is worth treating as real.

## What requires us

- **Fingerprint resolution.** `prov_fp_notable` is a keyed digest and the key never leaves us. A
  resolution request naming the digest returns what it was computed from. Without this the alert
  cannot be closed either way, which makes the turnaround for this particular request the
  difference between a usable detector and noise.
- **Spool pull** for both sessions, to see the content around each occurrence.
- **The full fingerprint sets**, which the flattened event reduces to one scalar, if the scheduled
  intersection job exists by the time you are reading this.

## Containment

Nothing automatic, and usually nothing immediate: by the time a fingerprint has propagated the
content has already moved. Recommend:

1. Identify and remove the shared artifact — the wiki page, ticket, or commit — if the fingerprint
   resolves to attacker-controlled content.
2. Treat every session that carried the fingerprint as exposed and review what each did afterward.
3. For a confirmed origin, the containment belongs to that session's detector (D4, D5 or D8), not
   to this one.

## Escalation

**Page** only on 100282 where the fingerprint resolves to something attacker-controlled, or where
the ingest side has a D4, D5 or D8 alert in its session.

**Queue** 100281 with differing session ids.

**Close without escalation** 100281 where both events share a session id. That is the expected
majority, and the tripwire's caveat rather than a finding.
