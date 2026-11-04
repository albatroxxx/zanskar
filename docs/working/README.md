# How we work

What a person joining this repository needs to know that the code does not say: how decisions are
made and recorded, how work is batched and shipped, what every change must pass, how the console
speaks, what security rules every change keeps, how the documentation is kept honest, and where
things live. Each page is short and names the rule, the reason, and an example from the history.

| Page | What it settles |
|---|---|
| [decisions.md](decisions.md) | Who decides what, ADRs, amendments, parking, the standards-first rule |
| [batches-and-releases.md](batches-and-releases.md) | Branches, local commits, one PR per batch, CI, merge, tag, release, verify, publish |
| [quality-gate.md](quality-gate.md) | Tests with every change, the break-it pass, the local gate, the rigs |
| [console-copy.md](console-copy.md) | How the console speaks: terse, no filler, no notices, four a row |
| [security-rules.md](security-rules.md) | Secrets, audit, routes, addresses, containers, posture statements, scanner triage |
| [docs-rules.md](docs-rules.md) | Plain words, honest history, screenshots that match, the site check |
| [engineering-conventions.md](engineering-conventions.md) | Go, SQL, migrations, tests, the console: the conventions and the guard tests |
| [repo-map.md](repo-map.md) | Where things live |

[CONTRIBUTING.md](../../CONTRIBUTING.md) is the setup and the pull-request checklist;
[GOVERNANCE.md](../../GOVERNANCE.md) is who may merge and release; [SECURITY.md](../../SECURITY.md)
is how to report a weakness. [docs/adr](../adr/README.md) holds every decision;
[docs/roadmap.md](../roadmap.md) says what is next and what is out of scope.
