# 0017. Database access via an ephemeral per-session client container

Date: 2026-09-23

## Status

Accepted

## Context

Zanskar brokers access to hosts over SSH, RDP, VNC and WinRM. A common, unmet need is
access to managed / PaaS **databases** — AWS RDS and Aurora, Cloud SQL, Azure Database —
where the "instance" is a database endpoint, not a shell host. People need an interactive
client (`psql`, `mysql`, `mongosh`, …) against those endpoints with the same brokering
guarantees Zanskar already gives shells: access gated by policy, credentials never exposed
to the user, session recording and audit, and nothing to install on the user's machine.

Two facts shape the design. First, this is a **new protocol class**, not a variation of an
existing one: there is no OS session, no guacd, no `sshgw`. Second, **client/server version
skew is real** — a `psql` 16 client against a PostgreSQL 13 server, a `mysql` 8 client
against 5.7 — and the right client per engine and version is best carried in a container
image rather than compiled into the gateway.

## Decision

Model a database as a target, and serve access through an ephemeral per-session container
that runs the version-matched client.

- **Database is a new target type.** A `database` target carries an engine
  (`postgres` | `mysql` | `mariadb` | …), a version, an endpoint and port, and a credential
  (ADR 0005). Policy governs who may reach which database target and in which mode. The
  target is agentless — nothing is installed on the database (ADR 0009); the container is
  Zanskar-side infrastructure, not an agent.
- **Access is an ephemeral per-session client container.** On connect the gateway spawns a
  short-lived container running the matching CLI client, connected to the target, and bridges
  the client's stdio to the browser terminal — reusing the xterm terminal, WebSocket
  transport and asciicast **recording** that SSH already uses. One container per session,
  torn down when the session ends.
- **Browser terminal first.** The interactive CLI in the terminal is the v1 experience,
  because it reuses recording and audit and is text-auditable. A web GUI client
  (CloudBeaver / pgweb) proxied to the browser is a possible later addition, not the starting
  point.
- **Audit depth is phased, and the path is designed for phase 2 from day one.**
  - *Phase 1 (broker).* The container connects directly to the database endpoint. Audit is
    session start/end plus the terminal recording (the SQL a user types is captured in the
    asciicast). Ships value quickly.
  - *Phase 2 (protocol proxy).* A Zanskar wire-protocol proxy (PostgreSQL, then MySQL) sits
    between the container and the database, giving **structured per-query audit, read-only
    enforcement, and allowed-database/schema policy**. The container is pointed at the proxy
    instead of the endpoint — the user experience does not change. Connect wiring targets a
    proxy address from the start so this drops in without a rework.
- **Credentials prefer short-lived cloud auth.** Where the provider supports it, the gateway
  mints a per-session token (AWS RDS IAM `rds-db:connect`) rather than using a stored
  password; static sealed credentials (ADR 0005) are the fallback. Credentials are injected
  into the container at spawn and never shown to the user.
- **Containment is non-negotiable.**
  - **Egress lockdown:** the session container may reach only the target endpoint:port. It is
    never a general network pivot inside the VPC.
  - **Hardened spawn path:** the gateway does not hand its main process raw Docker-socket
    access (socket ≈ host root). Spawning goes through a narrow, least-privilege interface
    (rootless runtime, or a small brokered helper with a fixed API).
  - **Locked-down containers:** `no-new-privileges`, read-only root filesystem, dropped
    capabilities, CPU/memory limits, a session TTL with a reaper so nothing leaks, and a cap
    on concurrent database sessions.
  - **Trusted images:** per-engine/version client images, pinned by digest and scanned in CI
    (Trivy is already wired).
- **Single-instance friendly.** The gateway's local container runtime hosts the session
  containers — the box already runs guacd and PostgreSQL in containers — so this lands
  without the HA / Kubernetes work. The same model maps to a per-session Kubernetes Job or
  Pod later.

## Consequences

- A high-value new capability — brokered PaaS database access — inside Zanskar's existing
  target / policy / session / recording / credential model. A database is "just another
  protocol" to the rest of the system.
- Phase 1 delivers quickly with session-level audit; phase 2 adds query-level audit and
  read-only enforcement with no change to how people use it.
- The container-spawn path is the principal new privilege surface; this ADR commits us to a
  hardened, narrow spawn interface rather than raw socket access, and to per-session egress
  confined to the database.
- Ongoing cost: a matrix of client images to build, pin and scan as engine versions move.
- Out of scope for the terminal UX: bulk/non-interactive workloads (piping large SQL dumps);
  the proxy phase or a dedicated path can address that later.
- GCP Cloud SQL and Azure Database fit the same target model behind the credential/auth
  abstraction when we add those providers.

## Addendum 2026-09-23: no credential leak — the client never authenticates

Implementation exposed a flaw in the broker-first plan above. If the session container runs
the client (`psql`/`mysql`) connected **directly** to the database, the credential has to be
in that container for the client to authenticate — and a client shell escape (`psql`/`mysql`
`\!`) lets the user read it back from the environment. Whatever the client authenticates
with, the user can extract. That breaks the "credentials ... never shown to the user"
guarantee, so the direct-connection broker is **not** used.

**Decision: the client never holds a credential.** A per-session proxy holds the credential
and authenticates to the database; the client container connects to the proxy over a private,
trusted channel with no password.

- **Mechanism:** a per-session **proxy sidecar** — pgbouncer (PostgreSQL), ProxySQL (MySQL) —
  on a private per-session Docker network, configured with the upstream credential and
  `trust` auth for the client. This reuses proven auth (SCRAM, caching_sha2) instead of
  hand-rolled protocol crypto. The client container has no credential and no network route to
  the database except through the proxy.
- **Phasing:** the proxy is therefore the *starting point* for database access, not a later
  add-on. Per-query audit and read-only enforcement still layer on afterwards — the proxy
  already sees the wire bytes. **PostgreSQL (pgbouncer) ships first; MySQL follows.**
- The session container still records its terminal (asciicast) and audits session start/end;
  the credential stays only on Zanskar's side, in the sidecar (isolated, ephemeral, not
  user-reachable), never in the client the user drives.

## Addendum 2026-09-24: pgbouncer auth mechanics and the Docker-access requirement

Live verification against a real PostgreSQL 16 (`scram-sha-256`) upstream settled two details
the sidecar decision above left implicit.

- **The proxy needs the plaintext password for the upstream, and `trust` for the client.**
  A `trust` client presents no password, so pgbouncer has nothing to forward and must
  authenticate to the server itself. With a modern (`scram-sha-256`) upstream this only works
  if pgbouncer holds the **plaintext** password — an md5/scram hash yields
  `cannot do SCRAM authentication: wrong password type`. So the `[databases]` entry carries an
  inline `user=/password=` (plaintext), `[pgbouncer] auth_type=trust`, and a `userlist.txt`
  that merely lists the client user (its password is ignored under trust but the user must
  exist).
- **The credential stays out of the host argument vector.** The pgbouncer config (with the
  password) is passed to the sidecar in an environment variable and written to
  `/etc/pgbouncer/pgbouncer.ini` by an in-container start-up snippet, then pgbouncer is exec'd.
  `docker inspect`/`ps` on the host show no secret in argv; it lives only in the sidecar's
  environment. The client container still receives neither the password nor the upstream host
  — verified by inspecting a live session's containers.
- **Operational requirement:** brokering spawns containers, so the gateway process needs access
  to the Docker daemon socket, which is root-equivalent on a stock Docker install. The hardened
  systemd unit grants it narrowly via `SupplementaryGroups=docker` (the service otherwise keeps
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`). Operators who do not use database
  access need not grant it. A rootless-Docker or socket-proxy posture is a future hardening.
- **Follow-ups unchanged:** MySQL (ProxySQL) next; per-query audit and read-only enforcement
  layer on at the proxy afterwards.
