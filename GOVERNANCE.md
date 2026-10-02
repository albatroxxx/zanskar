# Governance

Zanskar is an open-source project under the [Apache 2.0 licence](LICENSE). This document says who
decides what, how, and how the project keeps going if any one person stops.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| **Maintainer** | [@albatroxxx](https://github.com/albatroxxx), [@Lakshyabh06](https://github.com/Lakshyabh06) | Sets direction and the [roadmap](docs/roadmap.md); approves architecture decision records; reviews and merges pull requests; cuts and publishes releases; triages security reports under [SECURITY.md](SECURITY.md); enforces the [code of conduct](CODE_OF_CONDUCT.md). |
| **Committer** | none yet | Reviews and merges pull requests in the areas they know; triages issues. Cannot change repository settings or publish releases. |
| **Contributor** | anyone | Opens issues and pull requests under [CONTRIBUTING.md](CONTRIBUTING.md). |

Maintainers and committers are listed here by GitHub handle. A change to this table is a pull
request like any other, approved by a maintainer.

## How decisions are made

- **Day-to-day changes** are pull requests. A pull request merges when CI is green (the required
  checks on `main`) and a maintainer or committer other than its author has approved it.
- **Design changes** (a new protocol, security model, storage or trust decision) are proposed as an
  [architecture decision record](docs/adr/) first. A maintainer accepts or rejects it in the pull
  request that adds it; the reasoning stays on the record.
- **Disagreements** are settled in the pull request or issue. If people still disagree, the
  maintainers decide, and say why in the thread.
- **Security reports** follow [SECURITY.md](SECURITY.md): private advisory, acknowledgement within
  three business days, fix and credited advisory.

## Becoming a committer or maintainer

A contributor with a record of reviewed, merged pull requests can be proposed as a committer by a
maintainer, in a pull request to this file. A committer who has shown judgement on design and
security can be proposed as a maintainer the same way. Maintainers who step back move to an
emeritus line below and lose write access.

## Continuity

The project must keep going if any one person is unavailable. That means at least **two people**
with each of these, each using two-factor authentication on GitHub:

- administration of the `albatroxxx/zanskar` repository (settings, branch protection, secrets);
- merging pull requests and closing issues;
- tagging and publishing releases (the release workflow signs with its own keyless identity, so
  no private signing key has to be handed over);
- the GitHub Pages site, the OpenSSF Best Practices entry and the Scorecard setup.

Both maintainers can merge pull requests, close issues, and tag and publish releases. The
repository lives on a personal GitHub account, so its settings, branch protection, secrets, the
Pages configuration and the Best Practices entry are administered by its owner,
[@albatroxxx](https://github.com/albatroxxx), alone. Moving the repository to a GitHub
organisation would let a second person hold those too; until then, that single point is known
and stated here.

## Code of conduct

Everyone taking part follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Maintainers enforce it.
