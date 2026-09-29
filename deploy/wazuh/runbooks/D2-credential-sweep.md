# Runbook D2 — credential sweep

**Rules:** 100210–100212 (group `ambit_d2`). **MITRE:** T1552.001, T1555, T1098.

Credential paths get read one at a time by ordinary tooling and in bulk by staging for
exfiltration. This detector alerts on the bulk case, and separately on writes, which are
a different act.

| Rule | Level | Means |
| --- | --- | --- |
| 100210 | 5 | A credential-zone read (context; the building block) |
| 100211 | 12 | **8+ credential-zone reads in one session within 120s** |
| 100212 | 12 | A credential-zone **write** |

## What this alert asserts

- The endpoint classified the accessed path as being in the `credential` zone: SSH keys,
  cloud credential files, `.env` files, token stores, keystores. The label is cleartext
  and the path is a keyed digest, so you can act on the class without seeing the
  filesystem.
- For 100211: eight or more such reads inside two minutes, **in one session**
  (`same_field` on `session_id`), so this is one agent sweeping rather than a fleet-wide
  coincidence.
- For 100212: the operation was a write. `path_count` says how many paths that single
  tool call touched.

## What it does not assert

- **The threshold is a placeholder.** Eight in 120 seconds was set before fleet data
  existed. A monorepo with dozens of `.env` files trips it during an ordinary build or
  test run, and a secrets-management tool trips it by design. This is the detector most
  likely to need retuning from M2 baseline data, and saying so is more useful than
  pretending the number is meaningful.
- **Zone is a classification, not a judgement.** A `.env.example` committed to a repo is
  in the credential zone and contains nothing.
- **It does not distinguish the agent from the developer.** The events come from the
  agent's tool calls, but a developer can ask an agent to rotate credentials.

## Triage

1. **Look at `path_count` and the spread.** One tool call touching many credential paths
   (high `path_count`) is a glob or a recursive read — the sweep shape. Many separate
   calls each touching one path looks more like a tool walking a list.
2. **Check what else the session did.** Same `session_id`: `bash_command_class` =
   `network` (rule 100300), or a D1 alert, turns "read many credentials" into "read many
   credentials and then talked to the network". That combination is the escalation
   trigger; credential reads alone often are not.
3. **Check the prompt.** A prompt mentioning deploy, rotate, secrets or CI explains most
   of this detector's true positives-that-are-not-incidents. The text requires us.
4. **Check the timing against build activity.** A sweep inside the first seconds of a
   session, before any prompt, is automation. A sweep in the middle of a long session
   with many workdir reads is likely a test suite.
5. **For 100212, treat writes as more serious than reads by default.** Writing to a
   credential path is persistence — an added `authorized_keys` entry, a rewritten token
   file — not staging. There are fewer innocent explanations.

## What requires us

- **Digest resolution** for the paths, which is what separates forty `.env.example` files
  from four private keys. For this detector it is usually the only question that matters.
- **Spool pull** for the session's prompts and tool inputs.
- **`path_count` context**: the full path list for a single call, which the flattened
  event reduces to its highest-severity member.

## Containment

Not automatic. Recommend:

1. For 100212, revoke and re-issue whatever the written path holds, before analysis
   completes.
2. For 100211 correlated with egress, revoke the credentials in the resolved paths.
3. For 100211 with no egress and a plausible build explanation, no containment; feed the
   endpoint's pattern back to us so the threshold can be tuned.

## Escalation

**Page** on 100211 correlated with network egress or a D1 alert in the same session, and
on 100212 outside a prompt that explains it.

**Queue** 100211 alone, and 100210 bursts below the threshold.

**Do not page** a single 100210. It is context, and it is level 5 for that reason.
