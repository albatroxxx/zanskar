# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Email the maintainers (address to be published with the first release) with:

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

## Design references

- [Threat model](docs/threat-model.md)
- [Architecture decision records](docs/adr/)
