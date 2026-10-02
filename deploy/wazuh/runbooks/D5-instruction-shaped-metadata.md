# Runbook D5 — instruction-shaped MCP tool metadata

**Rules:** 100241–100248 (group `ambit_d5`). **MITRE:** T1195.002, plus T1552.001 or
T1041 where the finding names credentials or exfiltration.

An MCP tool's description and parameter descriptions are read by the agent's model as
part of its context. Text placed there is therefore instruction-shaped whether or not it
was meant to be, and a server can use that to steer an agent without exploiting
anything. This detector scans everything a server advertises — tool names, titles,
descriptions, parameter names and parameter descriptions — at the moment it advertises
it, before any tool has been called.

Server and tool names are in cleartext. **The matched text is not in the alert and
neither are the specific pattern ids**; only the finding classes are. Step 4 says how to
get the rest. That is deliberate: the text comes from an untrusted third party and does
not travel further than the endpoint it arrived on.

| Rule | Level | Class | Means |
| --- | --- | --- | --- |
| 100241 | 10 | `hidden_instruction` | Concealed or overriding instructions |
| 100242 | 10 | `role_assertion` | Metadata claiming a conversational role |
| 100243 | 12 | `cross_server_ref` | Refers to a *different* server's tools |
| 100244 | 7 | `sensitive_file_ref` | Names credential or secret paths |
| 100245 | 7 | `sensitive_action` | Describes exfiltration-shaped actions |
| 100246 | 13 | — | **Approved tool drifted into instruction-shaped metadata** |
| 100247 | 8 | — | Finding on an approved, unchanged tool: review our approval |
| 100248 | 12 | — | Concealed instructions across three or more tools of one server |

## What this alert asserts

- `tool_mcp_server` advertised a tool, `tool_mcp_tool`, whose metadata matched one or
  more D5 pattern classes, listed in `mcp_scan_classes`.
- The scan covered the description, the title, the tool name, and the parameter names
  and descriptions from the input and output schemas.
- `mcp_baseline_state` says whether that metadata is also new or changed:
  `approved` means this exact text was approved by a human and has not changed;
  `drift` means it changed after approval; `new` means first sighting.
- Rule **100246** asserts both halves at once: the tool's metadata changed from an
  approved baseline **and** what it changed into contains concealed instructions. That
  is the documented tool-poisoning sequence rather than a candidate for it, and it is
  the highest-confidence alert this detector produces.
- Rule **100247** asserts something about us, not the server: instruction-shaped text
  sits in a surface a human approved, and it has not changed since. Either the approval
  was wrong or a pattern was added after it.

## What it does not assert

Be direct with yourself about this detector's noise, because two of its five classes are
expected to produce false positives:

- **`sensitive_file_ref` fires on servers whose job is secrets.** A credential manager,
  a vault client, an SSH tooling server or a CI secrets integration describes
  credentials because that is its function. This is why the rule is level 7 and not
  level 12. A single `sensitive_file_ref` on a server whose name suggests secret
  management is very likely benign.
- **`sensitive_action` fires on HTTP clients.** A fetch tool, a webhook sender or a
  deploy tool legitimately describes posting data to a URL.
- **`hidden_instruction` fires on prescriptive documentation.** Real descriptions say
  "you must call `authenticate` first" because it is true. Prescriptive is not the same
  as concealed, and the pattern cannot tell them apart.
- **`role_assertion` fires on prompt-template servers.** A server whose purpose is
  returning prompts will contain "you are a…" as data.
- **It does not assert the agent was influenced.** Detection happens at advertisement.
  Whether any model output changed is not observable here, and this system does not
  claim it is: a prompt-injection classifier is an explicit non-goal of this system,
  and these patterns are one weak signal, never a boundary. Nothing was
  blocked.
- **The patterns are a first draft.** Every finding carries a stable pattern id on the
  endpoint precisely so a noisy pattern can be retired on measured evidence during M1.
  If you are seeing a class fire repeatedly and benignly, say which pattern id and we
  will retire it — that feedback is the intended use of this detector in M1, not an
  inconvenience.

## Triage

**Step 1 — check `mcp_baseline_state` first.** It reorders everything:

- `drift` (and therefore rule 100246 if the class is `hidden_instruction`): treat as
  hostile until explained. The text was reviewed, then changed into this. Go to runbook
  D4 step 1 in parallel; the two detectors describe one event.
- `new`: a server advertising this from the start. Judge it on the class and the
  server's purpose, below.
- `approved` (rule 100247): nothing about the server changed. This is a review finding
  about our own approval. Queue it; do not page.

**Step 2 — weigh the class against the server's purpose.** `tool_mcp_server` and
`tool_mcp_tool` are cleartext, which is usually enough to form a view. `sensitive_file_ref`
on a server named for secret management is expected. The same class on a server whose
purpose has nothing to do with credentials — a wiki, a ticket tracker, an image
converter — is the shape that matters: a tool describing credential paths it has no
reason to mention.

**Step 3 — `cross_server_ref` deserves separate attention.** It is level 12 with the
lowest false-positive rate of the five, because a server naming a *different* server's
tools has few innocent reasons to. This is the cross-server shadowing signature: one
server's metadata altering the model's behavior toward another server's tools. A server
referring to its own tools does not fire this rule. When it fires, note which other
server was named — that detail is on the endpoint, not in the alert, and it is worth
requesting at step 4.

**Step 4 — count the classes on one tool.** Multiple classes on a single tool is a much
stronger signal than one, because the classes describe different halves of an attack.
`hidden_instruction` with `sensitive_file_ref` and `sensitive_action` together is a
description that conceals an instruction, names credentials, and describes sending them
somewhere. Any one of those alone is ambiguous; the three together are not.

**Step 5 — correlate.** Same `endpoint_id`, surrounding hour:

- rule 100248 or several 100241s on one `tool_mcp_server` — a pattern across the
  surface points at the server or its supply chain rather than one bad entry.
- `kind` = `tool_pre`/`tool_post` with this `tool_name` — was the flagged tool actually
  called? Check `r2_a`, `r2_b`, `r2_c`, `prov_edge_count` and `path_zone` on those
  calls.
- `kind` = `instructions_loaded` with `config_trusted` false in the same session — a
  poisoned instruction file *and* poisoned tool metadata is a repo-level compromise,
  not a server-level one.

**Step 6 — decide.** Escalate when: rule 100246 fired; `cross_server_ref` fired on a
server with no plausible reason; three or more classes on one tool; rule 100248; or the
flagged tool was called and that call carries a provenance edge, a credential-zone path
or a non-empty `policy_decision`.

## What requires us

1. **Baseline pull with pattern ids** — the advertised text verbatim plus the specific
   pattern ids that matched, for one server and tool. The classes in the alert say
   *what kind* of thing matched; the pattern ids and the text say what actually did.
   For `cross_server_ref` this also tells you which other server was named. Held on the
   endpoint.
2. **Spool pull** — the calls to the flagged tool and their results, for the session.
3. **Digest resolution** — only where a correlated event's path matters; zone labels
   are already cleartext.

If the answer to a `sensitive_file_ref` or `sensitive_action` alert is "this server does
that for a living", send us the pattern id with that verdict. A retired pattern is a
better outcome than a queue that learns to close this class unread.

## Containment

Not automatic, and not yours to execute. Recommend to us:

1. For 100246 or a confirmed poisoned description: remove the server from the affected
   endpoints, or revoke approval so every listing alerts, and treat any credentials the
   flagged tool could reach as exposed if it was called.
2. For `cross_server_ref`: consider whether the *named* server's tools were called in
   the same session, and revoke that server's credentials rather than only the flagged
   one's. Shadowing aims at the other server.
3. For a `new` finding on a server nobody needs: removal from `.mcp.json` is cheaper
   than analysis.

## Escalation

**Page** on 100246; on 100243 where the server has no plausible reason to name another
server's tools; on 100241 or 100242 with `mcp_baseline_state` = `drift`; on 100248.

**Queue** 100241 and 100242 with state `new`, 100244, 100245, and 100247.

**Do not page** a single `sensitive_file_ref` or `sensitive_action` on a server whose
described purpose covers it. Note the pattern id, send it to us, and close it.
