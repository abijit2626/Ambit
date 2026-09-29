# Runbook D8 — poisoned instruction file

**Rules:** 100290–100292 (group `ambit_d8`). **MITRE:** T1195.002, T1546.

Claude Code reads instruction files — `CLAUDE.md`, `.claude/rules/*.md` — and treats their
contents as guidance. A file that arrives with a cloned repository or a dependency is
attacker-controlled content being read as instruction, which needs no exploit to work. This is
the repo-carried injection route, and `InstructionsLoaded` is the only event that reports it.

| Rule | Level | Means |
| --- | --- | --- |
| 100290 | 10 | **An instruction file was loaded from a path nobody classified as trusted** |
| 100291 | 13 | The same, from a zone that is untrusted in its own right |
| 100292 | 12 | 3+ untrusted instruction files in one session within 600s |

## What this alert asserts

- Claude Code loaded instructions from a file, and `config_trusted` is false: the path is not
  under any prefix the operator listed as a trusted repository.
- `config_zone` says where it came from, in cleartext: `workdir`, `home`, `untrusted`,
  `system`. The path itself is a keyed digest.
- For 100291, the zone is `untrusted` — a dependency directory, a downloads folder, or
  something git reports as recently created and untracked. **An untrusted zone overrides a
  trusted repository prefix**: a `CLAUDE.md` inside `node_modules` of an approved repo is
  dependency-carried, and the endpoint classifies it as untrusted for exactly that reason.
- `config_source` carries the load reason, which distinguishes a file read at session start
  from one pulled in mid-session.

## What it does not assert

- **False means "not on the list", not "known bad".** The commonest cause by far is a developer
  working in a repository nobody has added to the trusted-repo configuration. Early in a
  rollout this detector is mostly that, and the fix is configuration, not investigation.
- **It does not say what the file contains.** No instruction text reaches Wazuh. The file is on
  the endpoint and reading it requires us.
- **It does not assert the agent followed the instructions.** Loading is observable; influence
  on model behavior is not, and this system does not claim otherwise.
- **It does not cover instructions arriving by other routes** — an issue body through an MCP
  tool, a web page, a dependency's source read as a file. Those are ingest, covered by the R2
  bits and provenance in M2, not by this detector.

## Triage

1. **Check the zone first.** `home` or `workdir` with `config_trusted` false is usually an
   unlisted repository: ask the customer whether the path should be on the trusted list. `untrusted`
   (rule 100291) is the serious case and needs the file read.
2. **Check the load reason.** A file loaded at `session_start` is the repository the developer
   opened. One loaded mid-session, after the agent has been working, means something directed the
   agent to read it — check what preceded it in the same session.
3. **Correlate with what the session then did.** Same `session_id`: a D2 credential read, a
   network command (100300), or a denied call (100220) shortly after an untrusted instruction load
   is the sequence that matters. Instruction load alone, followed by ordinary work, usually is not.
4. **For 100292, look at the paths as a set.** Several untrusted instruction files in minutes
   suggests a session pulling in guidance from everywhere it can reach, which is either a
   monorepo with many sub-projects or an agent following instructions to look for more
   instructions.
5. **Ask for the file.** For 100291 this is the decisive step and everything else is preamble: the
   text either contains instruction-shaped content aimed at the agent or it does not.

## What requires us

- **The instruction file's contents**, and its git status: tracked or untracked, when it appeared,
  which commit or package introduced it. This is the artifact that resolves the alert.
- **Digest resolution** for `config_path_digest`.
- **The trusted-repo configuration** for the endpoint, so "not on the list" can be read as
  deliberate or as an oversight.
- **Spool pull** for the session, to see what the agent did after the load.

## Containment

1. For a confirmed poisoned file: remove or quarantine it, and treat every session on that
   endpoint since it appeared as suspect. If it arrived through a dependency, the package is the
   incident, not the endpoint.
2. Revoke credentials only where the session did something that reached them.
3. For an unlisted-but-legitimate repository, the action is a configuration change on our side —
   add the prefix — not containment.

## Escalation

**Page** on 100291, and on 100290 correlated with a credential read, an egress command or a denied
call in the same session.

**Queue** 100290 alone and 100292.

**Batch** 100290 alerts that resolve to the same unlisted repository, and send us the path so the
trusted-repo list can be corrected once rather than triaged repeatedly.
