# AgentDojo fixtures

`runs/` holds six run logs copied unmodified from the AgentDojo repository
(https://github.com/ethz-spylab/agentdojo, `runs/`), kept at their upstream paths. They are
real model runs, chosen to cover each outcome the adapter distinguishes: a successful
attack, a failed attack, a run with no attack, an injection task's goal requested by the
user, a run with a tool error, and a DoS attack.

AgentDojo is MIT licensed; its license is reproduced in `LICENSE-AgentDojo`.

Edge cases the published logs do not contain (the newer list-of-blocks message format,
missing tool-call ids, an errored run that AgentDojo still scores as `security: true`)
are written inline in `agentdojo_test.go`, so nobody mistakes them for real data.
