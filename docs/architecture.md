# Architecture

A high-level view of how Zanskar is built. The security view of the same system, with trust
boundaries and threats, is [threat-model.md](threat-model.md); each design choice below links the
[architecture decision record](adr/) that made it.

## What it is

One Go binary (ADR 0001) that sits between people's browsers and the machines and databases they
need. The browser never talks to a target. The gateway authenticates the person, checks policy,
fetches or receives a credential, opens the protocol connection itself, relays the session and
records it. Nothing is installed on targets (ADR 0009).

```
 Browser ──HTTPS/WSS──▶ zanskar gateway ──SSH / WinRM / SFTP──────────────▶ Linux, Windows
                         │    │    │
                         │    │    └──Guacamole protocol──▶ guacd ──RDP/VNC─▶ Windows, VNC hosts
                         │    └──────── per-session container ──PG / MySQL──▶ databases
                         │
                         ├── SQLite or PostgreSQL (state, sealed secrets, audit chain)
                         ├── recordings: local disk or S3-compatible storage
                         ├── identity providers: OIDC, LDAP / Active Directory
                         └── AWS APIs: STS AssumeRole, Auto Scaling, EC2
```

## Inside the binary

The gateway is one process. Its packages under `internal/` are split by domain:

| Area | Packages | Responsibility |
|---|---|---|
| HTTP and API | `server`, `httpx`, `auth` | TLS listener, JSON API, sessions and CSRF, role checks, the embedded web console |
| Identity | `user`, `group`, `idp`, `auth` | Local accounts (Argon2id, TOTP), OIDC and LDAP sign-in, group mapping |
| Inventory | `target`, `asg`, `cloud`, `credential`, `sshca` | Hosts, databases, autoscaling groups, vaulted credentials, the SSH certificate authority |
| Decision | `policy`, `access`, `ticket` | Who may reach what over which protocol, just-in-time grants, one-time connect tickets |
| Sessions | `connect`, `gateway/*`, `session`, `recording`, `recstorage` | Protocol bridges (SSH, WinRM, Guacamole, database relays), live session control, recording and storage |
| Evidence | `audit`, `logring` | Hash-chained audit log, SIEM export, the in-memory log ring |
| Secrets and keys | `keyring`, `crypto`, `tlscert` | Envelope encryption under the master key (ADR 0007), key rotation, the managed TLS certificate (ADR 0021) |
| Platform | `store`, `config`, `settings`, `lifecycle`, `version` | Database access and migrations, install-time and runtime settings (ADR 0020), restart and drain |

The web console is React and TypeScript built with Vite (ADR 0010) and compiled into the binary
behind the `webui` build tag.

## A session, end to end

1. The browser signs in over HTTPS (password, then TOTP; or an identity provider).
2. The person picks a target. `policy` decides whether they may connect over that protocol, and
   `access` checks for any just-in-time grant the policy requires.
3. `ticket` issues a short-lived, single-use connect ticket; the browser opens a WebSocket with it.
4. `connect` resolves the target, unseals the credential through `keyring` (or asks the person for
   one, or issues a short-lived SSH certificate through `sshca`), and opens the protocol:
   - SSH and WinRM directly from the gateway, with pinned host keys and certificates (ADR 0012);
   - RDP and VNC through the `guacd` sidecar (ADR 0002);
   - PostgreSQL, MySQL and MariaDB through an ephemeral client container, so the database
     password never reaches the person (ADR 0017).
5. The bridge relays the stream, writes the recording, and records `session.start` and
   `session.end` in the audit chain (ADR 0008). Admins can watch or end the session live.

## State

- **Database**: embedded SQLite for a single node, PostgreSQL otherwise (ADR 0003). Both run the
  same migrations.
- **Secrets**: every stored credential is sealed with a per-record data key, wrapped by a key ring
  under the master key. The master key is never stored in the database or in backups.
- **Audit**: insert-only, each event hashed onto the previous one; `zanskar audit verify` checks it.
- **Recordings**: asciicast for terminals, Guacamole format for desktops, on local disk or in an
  S3-compatible bucket, with retention per policy (ADR 0015).

## Deployment shapes

- **Package** (deb, rpm): one systemd service, hardened unit, `guacd` as a container beside it.
- **Container**: the same binary in a distroless image; Docker Compose adds `guacd` and Caddy.
- **Kubernetes**: a Helm chart, a preview until multi-replica control lands (roadmap Phase 4).

Zanskar 1.2 is single-instance: one gateway process per installation.
