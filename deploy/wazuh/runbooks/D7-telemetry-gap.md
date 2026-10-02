# Runbook D7 — telemetry gap

**Rules:** 100310–100314 (group `ambit_d7`), plus Wazuh's own rule 504. **MITRE:** T1562.001.

A monitor that stops reporting produces a calm alert stream, which is indistinguishable from a
quiet fleet unless something notices the silence. This detector exists because the adversary in
the threat model can kill processes, and because the most dangerous state this system can be in
is one where it looks fine.

Four signals, from three different places on purpose:

| Signal | Rule | What it catches |
| --- | --- | --- |
| The endpoint went dark | **504** (Wazuh's own, level 3) | The Wazuh agent stopped or the host is gone |
| ambitd is gone, agent alive | **100314** (SCA check 10007) | The daemon was killed; the endpoint still heartbeats |
| ambitd present but degraded | **100311**, **100312** | Dropped events, failing sinks, one collection path silent |
| Events were lost | **100313** | A window of the stream is unrecoverable |

## What this alert asserts

- **100311**: ambitd set its own health to `degraded`. That means one of: events were dropped, a
  sink write failed, OTLP exports are being rejected for the wrong encoding, or exactly one of
  the two collection paths (hook, OTel) has gone silent while the other is active. In every case
  the event stream from that endpoint is now incomplete.
- **100312**: the condition persisted across three heartbeats in fifteen minutes.
- **100313**: `health_dropped_events` is present, which by construction means non-zero. Dropped
  events are not recoverable; the sink writes a gap marker and continues.
- **100314**: the Wazuh agent's SCA scan found no `ambitd` process. The report comes from a
  different process than the one being reported on, which is what makes it survive an adversary
  who kills ambitd.

## What it does not assert

- **Absence is not alertable.** No rule here fires on "no heartbeat for N minutes", because a
  rule engine fires on events. 100314 is the substitute, and it runs on the SCA schedule rather
  than continuously — so there is a detection window equal to that interval.
- **The SCA parent SID and field names are unverified**. If 100314 has
  never fired on an endpoint where ambitd demonstrably stopped, suspect the wiring.
- **Both streams quiet is an idle endpoint, not a discrepancy.** The comparison ambitd makes is
  deliberately "exactly one silent", not a ratio: the hook and OTel paths legitimately see
  different things, so a count mismatch is normal.
- **Degraded does not say what was lost.** It says collection is incomplete, not which events
  are missing.

## Triage

1. **Establish which signal fired**, using the table above. They mean different things and have
   different containment.
2. **For 100311, get the reason from the endpoint.** The health event carries a status, not a
   cause; `health_queue_depth` and `health_dropped_events` narrow it, and ambitd's own log says
   plainly which condition it is — a rejected OTLP encoding, a full sink queue, or a silent
   stream. That log requires us.
3. **Check whether the endpoint is under load.** A full sink queue on a busy build machine is a
   capacity problem, not suppression. A full queue on an idle endpoint is not.
4. **For a silent-stream degradation, check what changed.** A D6 alert on `.claude/settings.json`
   in the same window suggests the hook was removed; a D12 failure on the OTel checks (10006,
   10008) suggests the exporter was redirected or switched to protobuf.
5. **For 100314 and 504 together**, the whole endpoint is gone and the question is why. For
   100314 alone, something stopped ambitd specifically while leaving the Wazuh agent running,
   which is a deliberate act far more often than an accident.
6. **Bound the gap.** Note the last event timestamp from that `endpoint_id` before the alert and
   the first one after recovery. Everything in between is unmonitored, and any later analysis of
   that window has to say so.

## What requires us

- **ambitd's log** for the degradation reason, and the endpoint's load at the time.
- **Whether the endpoint was expected to be off** — reboots, imaging, travel.
- **The gap boundaries** if the spool survived: the spool may contain events the SIEM never
  received, which is the one case where a gap is recoverable after the fact.

## Containment

1. Restart ambitd, and treat the gap window as unmonitored in any report covering it.
2. For a removed hook or a redirected exporter, restore from managed settings rather than by
   hand, then confirm the SCA checks pass.
3. For repeated 100314 on one endpoint, escalate as a possible deliberate suppression and review
   what the sessions on that endpoint were doing before the daemon stopped.
4. No credential action from this detector alone; it reports on the monitor, not on the agent.

## Escalation

**Page** on 100314, on 100312, and on 100313 where the dropped count is large enough that a
detector could plausibly have missed something.

**Queue** single 100311 events, and 504 for endpoints that are routinely offline.

**Escalate as an availability issue, same day, not on a threshold**, when degradation affects
several endpoints at once: that is a deployment problem, and the fleet is partly blind until it
is fixed.
