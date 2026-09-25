# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report privately through GitHub's private vulnerability reporting:
<https://github.com/albatroxxx/zanskar/security/advisories/new>. The report is visible only
to the maintainers and to you until a fix is published. Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the version or commit affected.

You will get an acknowledgement within 3 business days. We aim to ship a fix within 90 days and
will credit you in the release notes unless you prefer otherwise.

## Scope

Zanskar is an access gateway, so we treat the following as security issues:

- authentication or authorization bypass, including policy evaluation bugs,
- exposure of vaulted credentials, recordings, or audit data,
- session hijacking or cross-session data leakage,
- audit log tampering or gaps,
- anything that lets a user reach a target outside their policy.

## Supported versions

Until 1.0, only the latest minor release receives security fixes.

## Dependency advisories

`govulncheck` runs in CI on every push and the build fails on any vulnerability our code
actually calls. Advisories that reach only code paths we do not use are triaged here:

- **GO-2026-5932** — `golang.org/x/crypto/openpgp` is unmaintained. Zanskar does not import
  that package, and `govulncheck` confirms it is never called. The advisory has no fixed
  version, so there is nothing to upgrade to; `golang.org/x/crypto` is otherwise current and
  is required for SSH, Argon2id, and related primitives. No action needed — re-triage if an
  OpenPGP dependency is ever introduced.

## Design references

- Threat model: <https://github.com/albatroxxx/zanskar/blob/main/docs/threat-model.md>
- Architecture decision records: <https://github.com/albatroxxx/zanskar/tree/main/docs/adr>
- Published advisories: <https://github.com/albatroxxx/zanskar/security/advisories>
- OpenSSF Scorecard report: <https://scorecard.dev/viewer/?uri=github.com/albatroxxx/zanskar>
