<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img alt="Zanskar" src="docs/assets/logo.svg" width="440">
  </picture>
</p>

<p align="center">
  <img alt="Zanskar: agentless access" src="docs/assets/badge.svg">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-0E9F8E.svg"></a>
  <img alt="Go" src="https://img.shields.io/badge/go-1.27-0A1A2C.svg?logo=go">
</p>

# Zanskar

Zanskar is an open-source, **agentless** access gateway for machines and managed databases. Users open
a browser, pick a target, and get a terminal (SSH, WinRM), a desktop (RDP, VNC), or a database session
(managed PostgreSQL) without installing anything on the target. Every session is policy-controlled,
recorded, and audited — and access can be standing or granted just-in-time on approval.

The name comes from the Zanskar valley in Ladakh. Nothing else. The logo is a shell prompt
redrawn as a summit and a cursor.

## Why another one?

Most access gateways assume a fixed set of servers. Zanskar treats
**autoscaling groups as first-class targets**: enroll an AWS Auto Scaling group with a read-only IAM
role, Zanskar tracks the healthy pool, and when the instance you are on is terminated you are offered
a switch to another healthy instance instead of a dead terminal.

## What you get

- **Terminals** — SSH and Windows (WinRM), streamed to the browser over WebSocket and recorded as asciicast.
- **Desktops** — RDP and VNC through a guacd sidecar, with session recording and live shadowing.
- **Managed databases** — a `psql` session to PostgreSQL (Amazon RDS or self-managed) through an
  ephemeral, per-session client container. The database credential is held by a sidecar and **never
  reaches the user's client** (ADR 0017).
- **Autoscaling groups as targets** — enroll an AWS Auto Scaling group; Zanskar tracks the healthy pool
  and offers failover when the instance you are on goes away.
- **Just-in-time access** — approval-gated policies grant *eligibility*, not standing access: a user
  requests a target with a reason and a duration, an admin approves, and the grant is time-boxed and
  expires on its own (ADR 0018).
- **File transfer and clipboard** — SFTP for SSH and drive redirection for RDP, each gated by policy.
- **Identity, kept separate** — local accounts (Argon2id + TOTP), OIDC and LDAP/AD sign-in, and an
  SSH certificate-authority mode for keyless SSH.
- **Recorded and audited** — every session is recorded; the audit log is hash-chained with a `verify`
  command, and can be streamed to a SIEM.

## Principles

- **Agentless.** Targets need SSH, RDP, VNC or WinRM; a managed database needs only a reachable endpoint. Nothing is installed on them.
- **Browser never touches the target.** Only the gateway does. Targets need no inbound internet exposure.
- **Two authentications, kept separate.** Who you are to Zanskar (local, OIDC, LDAP/AD, MFA) is
  distinct from how Zanskar authenticates to a box (password, SSH key, SSH certificate, domain credentials).
- **Three roles.** `admin` configures and reviews, `auditor` reviews only, `user` connects. Every
  view of a recording or the audit log is itself audited.
- **Least standing privilege.** Access can be standing or just-in-time: sensitive targets are made
  eligible-only, so no one holds standing access — it exists only as a time-boxed, approved, audited grant.
- **Secure by default.** Envelope-encrypted secrets, hash-chained audit log, MFA, signed releases.

## Status

Phases 0–3.6 are complete — including SSH file transfer, managed-database access, and just-in-time
access approvals (PIM). The v1.0 single-instance scope is complete; the release is pending final
sign-off. See [docs/roadmap.md](docs/roadmap.md), the [threat model](docs/threat-model.md) and the
[architecture decision records](docs/adr/).

## Quick start (development)

```sh
cp .env.example .env
export ZANSKAR_MASTER_KEY=$(go run ./cmd/zanskar keygen)
go run ./cmd/zanskar migrate
go run ./cmd/zanskar admin create --username admin --name "Your Name"   # prompts for a password
make build          # builds the web UI and a single binary with it embedded
./bin/zanskar serve # SQLite, plain HTTP on 127.0.0.1:8443
```

Open http://127.0.0.1:8443, sign in, and enroll your authenticator when prompted. For UI work run
`make web-dev` (Vite on :5173, proxying to the API) beside `make run`. `zanskar audit verify`
checks the audit chain from the command line. If the only admin loses their authenticator,
`zanskar admin reset-mfa --username <name>` on the gateway host clears it and audits the reset;
the next login enrolls a new one.

Requires Go 1.27+ and Node 22+ to build.

Run the single-instance stack (gateway on SQLite, guacd, Caddy TLS) on one box:
`docker compose -f deploy/docker-compose.yml up -d --build`. For a Postgres-backed
development stack instead, use `deploy/docker-compose.dev.yml`.

## Layout

```
cmd/zanskar/      entrypoint
internal/         application code (not importable by other modules)
migrations/       SQL migrations, one set per database driver
docs/             threat model, ADRs, API spec, wireframes, roadmap
deploy/           Dockerfile, docker-compose, Helm chart
web/              React + TypeScript frontend, embedded into the binary at build time
```

## Deploying

Single node: `deploy/docker-compose.yml`. Kubernetes: the Helm chart in
`deploy/helm/zanskar`. Topology, high availability, upgrades, backups and the security
checklist are in [docs/deploy.md](docs/deploy.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

Apache License 2.0. See [LICENSE](LICENSE). The third-party components compiled into
the binary and their license texts are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (generated by `hack/gen-notices.sh`);
bundled non-code assets are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
