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
| 100280 | 1 | A session's first sighting of a notable fingerprint, an `fp_sighting` event sent by ambitd. Counted by the two rules below; below the default log alert level of 3, so it does not alert unless the manager's `log_alert_level` is set to 1 or 2 |
| 100281 | 10 | The same fingerprint seen in **two different sessions** within 3600s |
| 100282 | 12 | The **fifth sighting** of the same fingerprint across sessions within 7200s. That event alerts as 100282 instead of 100281 |
| 100283 | 12 | A provenance edge: the action carried a value that untrusted content introduced earlier in the same session |

## What this alert asserts

- Two or more different `session_id` values each sent an `fp_sighting` with the same
  `prov_fp_notable` inside the window. A session that repeats a fingerprint does not raise 100281:
  ambitd sends one `fp_sighting` per session and fingerprint, and the rule also requires the
  session to differ.
- An `fp_sighting` is ambitd's own event, not a tool call. Its `tool_use_id` names the
  `tool_post` that first carried the fingerprint in that session; that `tool_post` also carries
  `prov_fp_notable`, as does every later tool result in which the session saw it again.
- `prov_fp_notable` is a **keyed digest** of one high-specificity feature — a domain, an email
  address, or a high-entropy token — selected from the content of a tool result. Equality is all an
  analyst gets: two sessions saw the same thing. What that thing was requires resolution.
- 100282 means a fifth sighting of one fingerprint, across sessions, inside two hours: the event
  that brings 100281's conditions to a fourth match alerts as 100282. With each session sending a
  fingerprint once, it is a count of sessions seeing the same content.

## What it does not assert

- **It does not assert direction.** D10 means "ingested in X, emitted by Y". The rule sees sightings
  of a value and cannot order them. `prov_fp_role` is always `ingest` today: ambitd only looks at
  tool *results*, so the field cannot tell you which session emitted the content. Event
  timestamps order the sightings, but the earlier session is only a candidate origin, not proof of
  one.
- **It does not assert the content was malicious.** A shared internal domain in two agents' tool
  results is what a company wiki looks like. This detector's false-positive rate is expected to be
  high, which is why 100281 is level 10 and not 12.
- **A quiet D10 means little.** Three reasons it can stay silent while propagation happens:
  - ambitd only fingerprints tool *results*. Content that reaches an agent another way, a user
    prompt for example, carries no fingerprint.
  - Each session's memory of fingerprints it already sent is bounded (256 by default,
    `fp_notable_session_cap`). A full set forgets the oldest, so that fingerprint is sent again
    the next time the session sees it. That costs a repeat `fp_sighting` and never a missed one. A
    repeat from a session that already paired with another can raise 100281 again for the same
    two sessions, and add to 100282's count with fewer than five sessions involved (inferred; the
    cap has not been exercised against Wazuh). ambitd's memory also resets when it restarts; the
    different-session test is what keeps a restart from alerting by itself.
  - An ambitd build older than `fp_sighting` puts the fingerprint only on the `tool_post`, and
    these rules no longer count `tool_post` events. Hosts on those builds are invisible to D10
    (measured offline: twelve sessions of such `tool_post` events raised nothing).
- **A fingerprint is no longer lost to a louder alert on the same event.** A `tool_post` can
  alert as another rule: a network `curl` whose result holds a secret alerts as 100302. Wazuh
  counts an event only toward the rule that won it, so while D10 counted `tool_post` events those
  sightings were lost. The `fp_sighting` is a separate event that no other rule matches, so both
  alerts now stand (measured offline: twelve sessions whose even-numbered `tool_post` events alert
  as 100302 gave all six 100302 alerts and the same D10 count as twelve sessions without them).
- **The windows have not been exercised.** The rules were replayed offline, and replay is instant,
  so the 3600s and 7200s expiry is untested.
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

1. **Collect the sightings.** Pull every `fp_sighting` with this `prov_fp_notable` in the window,
   one per session, and the `tool_post` each one's `tool_use_id` names. Note each `session_id`, `endpoint_id` and `user_id`. Different sessions are
   guaranteed by the rule; the question is how different. Two sessions on one endpoint and one
   user is usually one developer with two terminals. Different `endpoint_id` or `user_id` is the
   case worth working.
2. **Order them by timestamp.** The earliest sighting is the candidate origin. It is not proof of
   direction (see above): all you know is who saw it first.
3. **Count the sessions and endpoints.** One fingerprint across five sessions on five endpoints
   (rule 100282) is either a widely shared internal resource or something spreading. The
   distinction is what the fingerprint resolves to.
4. **Resolve the fingerprint.** Until you know whether it is the company wiki domain or an
   attacker's host, nothing else is decidable. This requires us and it is the whole alert.
5. **Check the earliest session for a known-bad origin.** If it also has a D8 or D4 alert, or a
   100283 edge, you have a candidate origin and the propagation is worth treating as real.

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

**Queue** 100281. Every one is already a different-session pair.

**Close without escalation** a 100281 whose fingerprint resolves to a shared internal resource
(the company wiki, a common vendor domain) and whose sessions are all one user's. Record what
it resolved to in the ticket, so the next alert for the same fingerprint closes faster.
