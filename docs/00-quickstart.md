# Quickstart: what ambit is and how to try it

## What it does

A Claude Code agent works on a developer's machine with their files, credentials and network.
It also reads things nobody vetted: web pages, issues, package source, MCP tool results. Any of
those can carry instructions, and an agent that follows them can be steered into reading
`~/.ssh` or sending a token somewhere. Each step looks like ordinary work, so it goes unnoticed.

ambit is a monitor for that. It watches every action an agent takes and reports the ones that
look like that pattern: a value from an untrusted page turning up in an outgoing command, a
credential read with no human approving, a tool description that changed after someone
approved it, a connection the sandbox had to block. Today it only watches and alerts. It never
blocks or slows anything, on purpose: it has to be shown accurate before it is allowed to stop
anyone.

## The parts

- **`ambitd`**, on each machine. Claude Code reports every prompt, tool call and tool result to
  it through hooks. It writes everything to a local spool and decides what is worth a look.
- **`mcp-interpose`**, optional, in front of each MCP server. It records what tools the server
  offers and notices when that changes.
- **Wazuh**, one server for the team. Only the interesting events go there, with file paths and
  hosts replaced by keyed codes, so an outside security team can watch without seeing your
  code. Wazuh raises the alerts; each has a runbook in `deploy/wazuh/runbooks/`.

## Try it on your own machine

```sh
make build
./scripts/dev-local.sh             # install for your user and hook it into Claude Code
# ...use Claude Code as you normally would, for a few days...
./scripts/dev-local.sh --status    # what it collected, a leak check, and the M0 report
```

If something seems off:

```sh
~/.ambit/ambitd doctor -config ~/.ambit/config.json   # will ambitd hear from Claude Code?
~/.ambit/ambitd report -config ~/.ambit/config.json   # latency, loss, restarts, what would go to Wazuh
```

One thing to know: if you run Claude Code with its sandbox on, add `127.0.0.1` to
`sandbox.network.allowedDomains`, or the sandbox refuses the hooks and ambitd hears almost
nothing. `ambitd doctor` checks this.

## Roll it out to a team

1. Install it as a service on each machine: `sudo ./scripts/install-system.sh --binary bin/ambitd-<os>-<arch>`
   (Windows: `scripts/install-system.ps1`). `--status` shows how it is doing.
2. Set up a Wazuh 4.x manager with the rules in `deploy/wazuh/` (see its README).
3. Follow [docs/06-cohort-checklist.md](06-cohort-checklist.md): it lists what to fix first,
   the rollout order, and how to measure whether the first milestone passed.

## Where to read more

- [README](../README.md): the full picture, the roadmap and every known limitation.
- [docs/03-detection.md](03-detection.md): what each detector looks for, and how well it does.
- [docs/02-architecture.md](02-architecture.md): how the pieces fit, and what they cost.
