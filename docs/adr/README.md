# Architecture Decision Records

An ADR records one decision that is hard to reverse, the context that forced it, and what it costs.
We write one when a choice shapes the codebase, the deployment model, or the security posture.

## Format

Each file is `NNNN-kebab-case-title.md` and has four sections:

- **Status**: Proposed, Accepted, Deprecated, or Superseded by NNNN.
- **Context**: the problem and the constraints at the time. Include alternatives considered.
- **Decision**: what we chose, in one or two paragraphs.
- **Consequences**: what becomes easier, what becomes harder, and what we now have to do.

A decision is never edited into something else. To change it, write a new ADR that supersedes it
and update the status of the old one.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-go-single-static-binary.md) | Go, shipped as a single static binary | Accepted |
| [0002](0002-guacd-sidecar-for-rdp-and-vnc.md) | guacd sidecar for RDP and VNC | Accepted |
| [0003](0003-postgres-primary-sqlite-embedded.md) | PostgreSQL primary, SQLite embedded | Accepted |
| [0004](0004-apache-2-license.md) | Apache License 2.0 | Accepted |
| [0005](0005-separate-identity-auth-from-target-credentials.md) | Separate identity authentication from target credentials | Accepted |
| [0006](0006-roles-admin-auditor-user.md) | Roles: admin, auditor, user | Accepted |
| [0007](0007-envelope-encryption-for-secrets.md) | Envelope encryption for secrets | Accepted |
| [0008](0008-hash-chained-audit-log.md) | Hash-chained audit log | Accepted |
| [0009](0009-agentless-only-ssm-out-of-scope.md) | Agentless only, SSM out of scope | Accepted |
| [0010](0010-frontend-react-typescript-vite.md) | Frontend: React, TypeScript, Vite | Accepted |
| [0011](0011-autoscaling-health-model.md) | Autoscaling health model | Accepted |
