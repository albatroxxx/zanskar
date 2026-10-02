# 0026. Contributions need no DCO sign-off

Date: 2026-10-02

## Status

Accepted. Amends 0004 (Apache License 2.0), which asked for a `Signed-off-by` trailer on each
commit.

## Context

0004 said contributions come in under the Developer Certificate of Origin, signed with a
`Signed-off-by` line on every commit. It was never enforced, and no commit carries one.

Requiring it means installing the DCO GitHub app, which blocks any pull request containing a
commit without the line. Every contributor, the maintainers included, would then have to use
`git commit -s`, and a forgotten line means rewriting the commit. For first-time contributors
that is a common stumbling block.

Apache 2.0 already covers what the sign-off would record. Section 5 of the licence says a
contribution submitted to the project is under the licence's terms, unless the contributor
says otherwise. For OpenSSF Best Practices Silver, `dco` is a SHOULD, not a MUST.

## Decision

Contributions are accepted under Apache 2.0 through its section 5, with no `Signed-off-by` line
required. The project does not install the DCO app.

## Consequences

- Contributing needs no extra step, and no commit has to be rewritten for a missing line.
- There is no per-commit record of a contributor's certification beyond the licence itself.
- The `dco` Best Practices criterion is unmet, and that is a deliberate choice.
- Revisit if a foundation the project joins, or a company contributing to it, asks for DCO or a
  CLA. Adopting DCO later applies only to new commits; history need not be rewritten.
