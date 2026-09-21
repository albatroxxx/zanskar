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

Zanskar is an open-source, **agentless** access gateway for virtual machines. Users open a browser,
pick a box, and get a terminal (SSH, WinRM) or a desktop (RDP, VNC) without installing anything on
the target. Every session is policy-controlled, recorded, and audited.

The name comes from the Zanskar valley in Ladakh. Nothing else. The logo is a shell prompt
redrawn as a summit and a cursor.

## Why another one?

Most access gateways assume a fixed set of servers. Zanskar treats
**autoscaling groups as first-class targets**: enroll an AWS Auto Scaling group with a read-only IAM
role, Zanskar tracks the healthy pool, and when the instance you are on is terminated you are offered
a switch to another healthy instance instead of a dead terminal.

## Principles

- **Agentless.** Targets need SSH, RDP, VNC or WinRM. Nothing else.
- **Browser never touches the target.** Only the gateway does. Targets need no inbound internet exposure.
- **Two authentications, kept separate.** Who you are to Zanskar (local, OIDC, LDAP/AD, MFA) is
  distinct from how Zanskar authenticates to a box (password, SSH key, SSH certificate, domain credentials).
- **Three roles.** `admin` configures and reviews, `auditor` reviews only, `user` connects. Every
  view of a recording or the audit log is itself audited.
- **Secure by default.** Envelope-encrypted secrets, hash-chained audit log, MFA, signed releases.

## Status

Phase 0 (foundations). See [docs/roadmap.md](docs/roadmap.md), the
[threat model](docs/threat-model.md) and the [architecture decision records](docs/adr/).

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
checks the audit chain from the command line.

Requires Go 1.27+ and Node 22+ to build.

For PostgreSQL and guacd: `docker compose -f deploy/docker-compose.yml up`.

## Layout

```
cmd/zanskar/      entrypoint
internal/         application code (not importable by other modules)
migrations/       SQL migrations, one set per database driver
docs/             threat model, ADRs, API spec, wireframes, roadmap
deploy/           Dockerfile, docker-compose, Helm (later)
web/              React + TypeScript frontend, embedded into the binary at build time
```

## Deploying

Single node: `deploy/docker-compose.yml`. Kubernetes: the Helm chart in
`deploy/helm/zanskar`. Topology, high availability, upgrades, backups and the security
checklist are in [docs/deploy.md](docs/deploy.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

Apache License 2.0. See [LICENSE](LICENSE). Bundled third-party assets are listed in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
