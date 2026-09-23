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
