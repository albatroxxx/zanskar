<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img alt="Zanskar" src="docs/assets/logo.svg" width="440">
  </picture>
</p>

<p align="center">
  <img alt="Zanskar: agentless access" src="docs/assets/badge.svg">
  <a href="https://github.com/albatroxxx/zanskar/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/albatroxxx/zanskar?sort=semver&color=2B3A8C"></a>
  <a href="https://github.com/albatroxxx/zanskar/actions/workflows/ci.yml?query=branch%3Amain"><img alt="CI" src="https://github.com/albatroxxx/zanskar/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/albatroxxx/zanskar/security/code-scanning"><img alt="CodeQL" src="https://github.com/albatroxxx/zanskar/actions/workflows/codeql.yml/badge.svg?branch=main"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/albatroxxx/zanskar"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/albatroxxx/zanskar/badge"></a>
  <a href="https://www.bestpractices.dev/projects/14924"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/14924/badge"></a>
  <a href="https://github.com/albatroxxx/zanskar/actions/workflows/ci.yml?query=branch%3Amain"><img alt="Test coverage" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Falbatroxxx%2Fzanskar%2Fbadges%2Fcoverage.json"></a>
  <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/albatroxxx/zanskar?logo=go&color=0A1A2C"></a>
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-0E9F8E.svg"></a>
</p>

# Zanskar

Zanskar is an open-source, **agentless** access gateway for machines and managed databases. Users open
a browser, pick a target, and get a terminal (SSH, WinRM), a desktop (RDP, VNC), or a database session
(PostgreSQL, MySQL, MariaDB) — without installing anything on the target. Every session is
policy-controlled, recorded, and audited, and access can be standing or granted just-in-time on approval.

Zanskar is named after the [Zanskar Valley](https://en.wikipedia.org/wiki/Zanskar) in Ladakh, in the
Himalayas of northern India. The logo is a shell prompt redrawn as a summit and a cursor.

## Why another one?

Most access gateways assume a fixed set of servers. Zanskar treats
**autoscaling groups as first-class targets**: enroll an AWS Auto Scaling group with a read-only IAM
role, Zanskar tracks the healthy pool, and when the instance you are on is terminated you are offered
a switch to another healthy instance instead of a dead terminal.

## What you get

- **Terminals** — SSH and Windows (WinRM), streamed to the browser over WebSocket and recorded as asciicast.
- **Desktops** — RDP and VNC through a guacd sidecar, with session recording and live shadowing.
- **Managed databases** — `psql`, `mysql` or `mariadb` sessions to PostgreSQL, MySQL and MariaDB (Amazon
  RDS or self-managed) through an ephemeral, per-session client container. The database credential is
  held by a sidecar (pgbouncer, or the gateway's own relay) and **never reaches the user's client**; TLS
  to the database is per target, up to `verify-full` with your CA bundle.
- **Autoscaling groups as targets** — enroll an AWS Auto Scaling group with a read-only cross-account
  role. The gateway knows its own AWS principal, prints the CLI script or CloudFormation template that
  creates the role, and tests the role before saving. Zanskar then tracks the healthy pool and offers
  failover when the instance you are on goes away.
- **Just-in-time access** — a policy can grant *eligibility* instead of standing access: a user requests
  a target with a reason and a duration, an administrator approves, and the grant is time-boxed, can be
  extended, and expires on its own. Policies carry per-target protocol rules, session limits and a
  recording retention of their own.
- **File transfer and clipboard** — SFTP for SSH and drive redirection for RDP, each gated by policy.
- **Keyless SSH** — an SSH certificate authority is the recommended way to reach Linux targets: Zanskar
  generates the authority, prints the one `TrustedUserCAKeys` line each target needs, mints a
  minutes-long certificate per session naming the Zanskar user in the target's auth log, and rotates the
  authority in two steps without breaking a host that has not learned the new key yet.
- **Identity, kept separate** — local accounts (Argon2id + TOTP, onboarding with a one-time password
  replaced at first sign-in), OIDC and LDAP/AD sign-in.
- **Recorded and audited** — every session is recorded; recordings and command transcripts can be
  downloaded, with every view and download audited; the audit log is hash-chained with a `verify`
  command and can be streamed to a SIEM.
- **Operated from the console** — HTTPS out of the box with a gateway-managed certificate you replace
  on the Settings page, runtime settings applied live, a restart-required banner when the environment
  file drifts, recording storage moved to an S3-compatible bucket without a restart, and the gateway's
  recent log lines on a Logs page.

## Principles

- **Agentless.** Targets are reached over SSH, RDP, VNC or WinRM; a managed database needs only a
  reachable endpoint. There is no agent to install on the target.
- **The browser never touches the target.** Only the gateway does, so targets need no inbound internet exposure.
- **Two authentications, kept separate.** Who you are to Zanskar (local, OIDC, LDAP/AD, MFA) is
  distinct from how Zanskar authenticates to a target (password, SSH key, SSH certificate, domain credentials).
- **Three roles.** `admin` configures and reviews, `auditor` reviews only, `user` connects. Every
  view of a recording or the audit log is itself audited.
- **Least standing privilege.** Sensitive targets can be made eligible-only, so no one holds standing
  access — it exists only as a time-boxed, approved, audited grant.
- **Secure by default.** Envelope-encrypted secrets, a hash-chained audit log, MFA, and signed releases.

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
the next login enrolls a new one. `zanskar key status`, `key rotate` and `key rotate-master`
manage the key ring and the master key; `zanskar dbproxy` is the MySQL/MariaDB relay the gateway
runs beside a database session, not something to start by hand.

Requires Go 1.27+ and Node 22+ to build.

Run the single-instance stack (gateway on SQLite, guacd, Caddy TLS) on one box:
`docker compose -f deploy/docker-compose.yml up -d`. For a Postgres-backed
development stack instead, use `deploy/docker-compose.dev.yml`.

## Deploying

The product site at <https://albatroxxx.github.io/zanskar/> has the installation guide,
the how-to guide and release notes in one place.

Zanskar 1.2 is a **single-instance** deployment: one gateway, embedded SQLite or PostgreSQL, and a
guacd sidecar for RDP/VNC. Two supported install paths, both from the
[releases page](https://github.com/albatroxxx/zanskar/releases):

- **Packages** (recommended): `.deb` / `.rpm` for amd64 and arm64, then `sudo zanskar init`
  writes the configuration, serves HTTPS on 443 with a certificate it manages (upload yours on the
  Settings page), and prints the next steps. `zanskar init -behind-proxy` keeps the gateway on
  loopback behind your own TLS proxy. Plain tarballs are there too.
- **Container**: `ghcr.io/albatroxxx/zanskar:latest`, or a pinned `:<version>`, with
  `deploy/docker-compose.yml` (gateway + guacd + Caddy TLS). `ZANSKAR_VERSION` in `deploy/.env`
  pins it; it defaults to `latest`. The same image is the MySQL/MariaDB relay sidecar, so a
  gateway that serves database targets needs Docker or Podman.

There is also a one-line path for a quick look, which needs only a Go toolchain:

```sh
go install github.com/albatroxxx/zanskar/cmd/zanskar@latest
```

That binary has **no web console** (the console is compiled in behind the `webui` build tag) and
reports its version as `dev`, because `go install` sets no linker flags. Use it for the CLI, the
API and trying things out; use a package or the container image for a real deployment.

Checksums and the image are signed with Sigstore; the release notes carry the `cosign verify`
commands. The Helm chart in `deploy/helm/zanskar` is a **preview**: it deploys, but multi-replica
HA (cross-pod terminate and shadowing) is Phase 4 work and not supported in 1.2. Topology,
upgrades, backups, TLS, recording storage, database access, AWS enrolment, the certificate
authority and the security checklist are in [docs/deploy.md](docs/deploy.md).

## Layout

```
cmd/zanskar/      entrypoint
internal/         application code (not importable by other modules)
migrations/       SQL migrations, one set per database driver
docs/             threat model, API spec, design decisions (ADRs), wireframes
deploy/           Dockerfile, docker-compose, Helm chart
web/              React + TypeScript frontend, embedded into the binary at build time
```

## Quality and security signals

Every badge above is computed from this repository by an open-source tool and links to its evidence.

| Badge | What it measures | Source |
|---|---|---|
| CI | Build, `go vet`, race tests on SQLite and PostgreSQL, golangci-lint, govulncheck, gosec, gitleaks, Trivy, third-party-notice check, all on every push and PR | [`ci.yml`](.github/workflows/ci.yml) |
| CodeQL | Static analysis of the Go server and TypeScript UI with the `security-extended` query suite; alerts appear in the Security tab | [`codeql.yml`](.github/workflows/codeql.yml) |
| OpenSSF Scorecard | Supply-chain hygiene scored 0 to 10 by the [OpenSSF](https://scorecard.dev): pinned dependencies, token permissions, branch protection, SAST, vulnerability status, and more. Weekly and on every push to main | [`scorecard.yml`](.github/workflows/scorecard.yml) |
| OpenSSF Best Practices | The [OpenSSF Best Practices](https://www.bestpractices.dev/) criteria for FLOSS projects: documented contribution and vulnerability-reporting process, tests and CI, static and dynamic analysis, published cryptography, secure delivery. Answers are public and linked to their evidence | [project 14924](https://www.bestpractices.dev/projects/14924) |
| Test coverage | Total statement coverage from the CI test run, written to the `badges` branch after each push to main | [`ci.yml`](.github/workflows/ci.yml) |
| Go version | Read from `go.mod` | shields.io |

Vulnerability handling and the current advisory triage are in [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. To report a bug or suggest something, open an issue — the **bug report**
and **feature request** forms will walk you through what to include. Please do not file security
problems as public issues; see [Security](#security) below.

To work on the code, [CONTRIBUTING.md](CONTRIBUTING.md) has the setup, the checks that must pass,
and the project conventions. The short version:

```sh
make all   # runs the linters, the race-detector tests, and builds the UI + binary
```

## Security

Zanskar is an access gateway, so security reports matter. See [SECURITY.md](SECURITY.md) for how to
report a vulnerability privately — never open a public issue for a security problem. The
[threat model](docs/threat-model.md) describes what Zanskar defends against.

## License

Apache License 2.0. See [LICENSE](LICENSE). The third-party components compiled into
the binary and their license texts are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (generated by `hack/gen-notices.sh`);
bundled non-code assets are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
