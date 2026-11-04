# How decisions are made

## Who decides

The project has an owner who decides what Zanskar is and is not (GOVERNANCE.md names the
maintainers). Engineering proposes; the owner decides; the record is written down. A contributor
who disagrees with a decision opens an issue that names the ADR, not a pull request that undoes it.

## Every design decision is an ADR

A change that alters how Zanskar is shaped — a new kind of target, a new way of authenticating, a
new place a secret lives, a new protocol, a setting that applies to everyone — starts as an ADR in
`docs/adr/`, numbered, with **Status**, **Context**, **Decision** and **Consequences** (the format is
in [docs/adr/README.md](../adr/README.md)). The ADR is written *before* the code and in plain words:
what is wanted, the facts that shape the answer, the decision as numbered points, what it costs,
and the open questions for the owner at the end. A small fix needs no ADR; a settings key that
everyone sees usually does.

An ADR's status moves: **Proposed** → **Accepted** (with the date and, when the owner changed
something, what) → built, or **Parked** (accepted, set aside, nothing built; the plan is the record,
as [ADR 0045](../adr/0045-kubernetes-clusters-as-targets.md) is) → or **Withdrawn** (the decision was
wrong or was never asked for; say so in a dated section rather than deleting it, as
[ADR 0021](../adr/0021-managed-tls-certificate.md)'s Let's Encrypt amendment was withdrawn).

**Amendments, not rewrites.** When a decision grows, add a dated `## Amendment, <date>` section
to the ADR that holds it ([ADR 0037](../adr/0037-application-modes-proxied-and-isolated.md) has three). The original
text stays, so a reader sees how the design got here. The index in `docs/adr/README.md` lists every
ADR; a file without a row is a mistake (0044 went unlisted for two days).

## The rules that decide most things

- **Standards first; a vendor adapter only beside the standard path.** Single sign-on is OIDC;
  directory sync is SCIM 2.0 and LDAP; cluster access will be the Kubernetes API with
  impersonation. A Keycloak, Okta, Entra, EKS or GKE adapter may exist, next to the standard path
  and never instead of it, and it must be checked against a second vendor before it ships (Keycloak
  and Authentik both run in `hack/`).
- **Agentless.** Nothing is installed on a target ([ADR 0009](../adr/0009-agentless-only-ssm-out-of-scope.md)).
  Zanskar's own containers on the gateway host are infrastructure, not agents.
- **Nothing the owner did not ask for.** A fourth tile to fill a row, a global setting nobody
  wanted, a feature folded in because it was easy: all of these were built once and all were
  removed on review. When a row needs a fourth box, use something that existed; when a feature
  overlaps an existing card, fold it in; before adding a global setting, ask.
- **Security over convenience, said plainly.** When a release widens what a session can reach, the
  release notes say so first, in bold, before the features (1.17.0 and 1.18.0 both did).
- **What is out of scope stays out.** [docs/roadmap.md](../roadmap.md) lists what the project will
  not do (install agents, rotate static keys, use AWS SSM). An idea against that list is a
  conversation with the owner, not a branch.

## Parked is a decision too

An idea the owner has heard and set aside is written down as parked — in the ADR if it has one, in
the issue otherwise — with the date and the reason. It is not raised again until the owner raises
it. Examples: live dashboard metrics (option chosen, build parked), WebAuthn as a second factor
(ADR 0028 approved, build parked), the Kubernetes kind (ADR 0045, accepted and parked).

## How a question is answered

When a contributor is unsure what the owner wants, the order is: the ADRs, then the release notes
(which explain *why* each thing changed), then an issue with the question and a recommendation. A
recommendation is one answer with its reason, not a survey of options; the owner picks or
redirects. Never assume consent: "note this decision down only for now" means record it and build
nothing.
