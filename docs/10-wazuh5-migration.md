# 10 — Q12 decided: stay on 4.x, and the 5.x gap is worse than assumed

[07](07-open-questions.md) Q12 was written against secondary sources — Wazuh's own
GitHub migration issues, not a release or a line of the new engine's code — and said
so. This is that reading, against the actual 5.0 source and Wazuh's own first-party
migration guide, both read at the versions cited below.

**Decision: keep building M0–M2 against 4.x. The recommendation does not change, but
the reason gets sharper and the timeline gets shorter.** 5.0 is no longer a future
possibility to price in later — it is in beta now, with 5.1 already the tip of
`main`. And the specific primitives this design's Wazuh half leans on hardest —
`frequency`/`timeframe`, `same_field`, `if_matched_sid` — are not "renamed or
reshaped" in 5.x. Wazuh's own migration guide lists them as **not supported in the
rule format at all**, with no shipped replacement, and its own worked example tells a
migrator to "document as a gap" rather than offering a mapping. That is a stronger and
more urgent finding than Q12's original framing of "primitives need equivalents
confirmed."

Evaluated against `wazuh/wazuh` at tag `v5.0.0-beta5` (commit `49b96be`, `VERSION.json`
reports `5.0.0-beta5`; `main` at commit `ef75192`, dated 2026-09-28, is already
`5.1.0-alpha0`) and `wazuh/wazuh-indexer-plugins` at its current default-branch tip
(commit `7288aef`). Both are public, both cloned read-only, no write access used.

## What was checked, and how

| # | Question Q12 left open | Resolved by |
| --- | --- | --- |
| 1 | Does the new engine have a `rule` asset at all? | `src/engine/source/builder/src/syntax.hpp`, repo-wide grep for `analysisd` |
| 2 | Do `frequency`/`timeframe`/`same_field`/`if_matched_sid` have 5.x equivalents? | `docs/guide/migration/rules-4x-to-5x.md` (shipped in-tree, not a GitHub issue) |
| 3 | Does ambit's flattened-JSON, no-custom-decoder approach still work? | `wazuh-indexer-plugins/wcs/stateless/events/main/docs/wcs_flat.yml`, `docs/ref/modules/ruleset-management/rules.md` |

## 1 — The legacy rule engine is gone, and the new one has no `rule` asset

Confirmed, completely. `src/analysisd` — the C daemon that has been the entire 4.x
rule engine — does not exist anywhere in the 5.0.0-beta5 tree; a directory listing at
the repo root and at `src/` both come back empty for it. It has been replaced by
`src/engine`, a new component whose asset model is declared in
`builder/src/syntax.hpp::name`: exactly five resource kinds are recognized —
`decoder`, `output`, `filter`, `integration`, `policy`. **There is no `rule` kind in
the engine at all.** A repo-wide, case-insensitive search for `frequency`,
`same_field`, `if_matched_sid` and `timeframe` across the entire `src/engine` tree
returns zero hits outside one unrelated test file (`fastmetrics`, about metric-sample
frequency, not rule correlation). The top-level `ruleset/` directory that used to hold
`rules/*.xml` and `decoders/*.xml` now holds only `mitre/` and `sca/` — no rule or
decoder content ships in the manager package itself.

This means the engine's job in 5.x is narrower than analysisd's was: decode, normalize
to a common schema, and route to an index. Detection is not part of it.

## 2 — Detection moved to a separate OpenSearch plugin, and correlation has no home there either

Confirmed, and this is the load-bearing finding. `wazuh/wazuh`'s own in-tree migration
guide (`docs/guide/migration/rules-4x-to-5x.md` — first-party, shipped in the product
repo, not a secondary blog or issue thread) describes the actual replacement
architecture:

1. **Wazuh Engine** decodes and normalizes events into the Wazuh Common Schema (WCS,
   an ECS derivative) and indexes them into `wazuh-events-v5-*`.
2. **A ruleset-management / content-manager plugin** (in `wazuh-indexer-plugins`)
   evaluates Sigma-format YAML rules via **percolator queries** against those indexed
   events. A match produces a **finding** (an enriched copy of the event) into
   `wazuh-findings-v5-*` — terminology has changed too: there are no "alerts" in 5.x,
   only events and findings.

The guide's own comparison table states plainly, in its "Correlation" row:

> `frequency`, `timeframe`, `same_*`, `different_*` → **Not natively supported in the
> rule format**

and its step-by-step migration section repeats this as an instruction, not a
limitation to work around:

> **Correlation rules** (`frequency`, `timeframe`, `same_*`, `different_*`) → Handle
> via a separate correlation engine or pipeline (**outside the rule format**).

The guide's own worked example is the clearest evidence available. It walks through
migrating a three-rule 4.x chain — a grouping rule, a leaf rule, and a correlation
rule (`frequency="8" timeframe="120"` with `if_matched_sid`, i.e. exactly D2's shape).
Its instruction for the correlation rule is not a mapping: it is *"cannot be migrated
directly — `frequency`/`timeframe`/`if_matched_sid` require a correlation engine.
**Document as a gap.**"* That is Wazuh's own migration authors, writing the official
guide, unable to offer their own users a path for this rule shape. No "separate
correlation engine or pipeline" exists in either repository as of beta5 — this was
confirmed by the same repo-wide search in finding 1.

**Direct consequence for ambit's rules:** D2 (credential-sweep, correlates repeated
reads via `frequency`/`timeframe`), D10's propagation tripwire (`same_field` on the
provenance fingerprint), and D11 (fail-open-run correlation) have no mechanism to move
to in 5.x today — not an undocumented mapping, a genuinely absent one. `if_sid` /
`if_group` rule chaining (used throughout the 58 rules shipped in M1 to scope
correlation and severity escalation to a parent match) is also gone; the guide's
replacement is "flatten into one self-contained rule," which is a real rewrite of
every multi-level rule in the set, not a syntax change.

## 3 — The field model changes underneath every rule, and ambit's zero-custom-decoder approach does not survive it

Confirmed. Today, `ambitd` writes its own flattened JSON directly to a file; the Wazuh
agent tails it with `log_format json`; Wazuh's built-in JSON decoder auto-extracts
whatever field names appear; ambit's rules match on those field names directly.
[README](../README.md) states this is deliberate: *"there is no custom decoder."*

`wazuh-indexer-plugins/docs/ref/modules/ruleset-management/rules.md` states the 5.x
constraint directly: *"All fields referenced in the `detection` section are validated
against the Wazuh Common Schema. Rules that reference unknown fields are rejected with
a structured error response identifying the offending field names."* WCS is a fixed,
ECS-derived field set (`wcs/stateless/events/main/docs/wcs_flat.yml`), not an
open schema that grows to match whatever a decoder emits. This inverts the current
approach: instead of ambitd's own field names flowing through unchanged, ambit would
need a real Engine `integration` — a purpose-built `decoder` asset that maps ambitd's
JSON into WCS-valid paths — before any rule could reference the result at all. None of
`r2_a`/`r2_b`/`r2_c`, `path_zone`, `mcp_baseline_state`, `secret_kind`, or any other
field in [04](04-data-model.md)'s flattened schema is a WCS field, and the guide states
rule creation fails closed (a structured rejection, not a silent no-match) on any field
that isn't.

**One plausible escape hatch, not yet confirmed against a working example.** WCS
carries the ECS `labels` field verbatim (`wcs_flat.yml` line 7733): *"Custom key/value
pairs... Should not contain nested objects. All values are stored as keyword,"*
`type: object`, `object_type: keyword` — exactly the shape most of ambit's genuinely
custom fields need. If `labels.<key>` passes the Content Manager's field validator the
way the schema entry implies, most of ambit's custom fields could live there
essentially unchanged, while the handful with a real ECS equivalent (paths →
`file.path`, action-shaped fields → `event.action`, IPs → `source.ip`/`destination.ip`)
should move to those paths instead, both to pass validation and to interoperate with
other Wazuh content that already uses them. Neither repository's docs show a worked
`labels.*` example inside a `detection` block, so this is recorded as a plausible
reading of the schema, not a confirmed mechanism — the next step if this is ever acted
on is a `labels.*` selection against a live Content Manager `logtest` call, not another
document.

The guide also confirms there is **no automatic conversion tool** — "Rules must be
manually rewritten following this guide" — so every one of the 58 rules shipped in
[M1](../README.md) would be a hand migration regardless of the correlation gap.

## What this changes about Q12's recommendation, and what it doesn't

**Doesn't change:** build M0–M2 against 4.x. `wazuh-logtest` and the primitives this
design uses are verified and field-proven there; nothing above makes 4.x less correct
today, and 4.x is not deprecated by 5.0's beta release.

**Sharpens:**

- The recommendation to "keep the rule set small and generated from a single source of
  truth so a migration is a re-render, not a rewrite" is still good practice, but it no
  longer fully applies: a re-render cannot manufacture a correlation primitive the
  target platform doesn't have. D2/D10/D11 specifically would need a redesign, not a
  re-render, if the fleet ever moves to 5.x as it stands today.
- "Needs an owner to track the 5.0 release and confirm the primitives" becomes
  narrower and more urgent: the thing to track is **whether Wazuh ships the
  "separate correlation engine or pipeline" its own guide gestures at**, since that
  determines whether a 5.x migration is a large rewrite or a currently-impossible one
  for this design's three correlation-dependent detectors. 5.0 beta5 shipped
  2026-09-07 by this checkout's commit date; 5.1 alpha work is already underway on
  `main`. This is closer than "targeting 4.x means a migration later" implied.
- Any future 5.x migration plan should budget for three separable pieces of work, not
  one: (a) a real Engine integration with a purpose-built decoder mapping ambitd's
  schema to WCS paths — likely `labels.*` for the custom fields, pending the
  verification noted above — (b) hand-rewriting every rule in Sigma YAML against that
  mapping, and (c) a design decision for D2/D10/D11 specifically, independent of (a)
  and (b), since no rewrite of the other 55 rules touches this gap.

## Reproducing this evaluation

```sh
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 https://github.com/wazuh/wazuh
cd wazuh
git fetch --depth 1 origin tag v5.0.0-beta5 && git checkout v5.0.0-beta5

# Finding 1: no analysisd, no `rule` asset kind in the new engine.
ls src/analysisd 2>&1                       # No such file or directory
grep -n '_PART =' src/engine/source/builder/src/syntax.hpp
grep -rli 'frequency\|same_field\|if_matched_sid\|timeframe' src/engine/source \
  --include='*.hpp' --include='*.cpp'

# Finding 2: the in-tree migration guide's own correlation verdict.
sed -n '60,80p' docs/guide/migration/rules-4x-to-5x.md    # the comparison table
sed -n '628,677p' docs/guide/migration/rules-4x-to-5x.md  # "document as a gap"

cd ..
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 https://github.com/wazuh/wazuh-indexer-plugins
cd wazuh-indexer-plugins

# Finding 3: closed-schema field validation, and the `labels` escape hatch.
grep -n 'validated against the Wazuh Common Schema' \
  docs/ref/modules/ruleset-management/rules.md
grep -n -A 12 '^labels:' wcs/stateless/events/main/docs/wcs_flat.yml
```
