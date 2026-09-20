# Zanskar Threat Model

Status: living document. Last reviewed 2026-09-20. Target assurance level: OWASP ASVS Level 2.

This document describes what Zanskar protects, who wants to break it, how they might try, and what
we do about it. It is the reference for design reviews and for the security review of every pull
request that touches authentication, authorization, credentials, session handling, or audit.

## 1. System overview and trust boundaries

Zanskar is an agentless access gateway. A user's browser never talks to a target machine. The
gateway terminates the browser connection, evaluates policy, retrieves or receives a credential,
opens a protocol connection to the target, and relays the session while recording it.

```
                 TB1                TB2                 TB3
  Browser  <--HTTPS/WSS-->  Zanskar gateway  <--guac proto-->  guacd sidecar  <--RDP/VNC-->  Target
                                   |                                                       ^
                                   |<-------------------------- SSH / WinRM --------------|
                                   |
              TB4 | TB5 | TB6 | TB7
                  |     |     |     \
             PostgreSQL |  AWS APIs  Identity providers (OIDC, LDAP/AD)
                   Object storage (recordings)
```

| Boundary | Between | What crosses it |
|---|---|---|
| TB1 | Browser and gateway | Login credentials, MFA codes, session cookies, keystrokes, screen data, clipboard, file transfers |
| TB2 | Gateway and guacd | Guacamole protocol: target address, target credentials in the connect handshake, screen and input stream |
| TB3 | Gateway or guacd and targets | SSH, RDP, VNC, WinRM. Target credentials, host keys, TLS certificates, session content |
| TB4 | Gateway and PostgreSQL or SQLite | Users, policies, wrapped DEKs, ciphertext credentials, audit events, session metadata |
| TB5 | Gateway and object storage | Recording files and their integrity hashes |
| TB6 | Gateway and AWS APIs | STS AssumeRole with ExternalId, Describe calls, optional EC2 Instance Connect key push |
| TB7 | Gateway and identity providers | OIDC tokens, LDAP bind credentials, user attributes and group membership |

The gateway is the only component that holds plaintext target credentials, and only for the lifetime
of a connect handshake. guacd receives plaintext RDP and VNC credentials because the protocol
requires it. That fact drives the network isolation requirement on guacd in section 5.

## 2. Assets, ranked by sensitivity

| Rank | Asset | Why it matters | Where it lives |
|---|---|---|---|
| 1 | Master key (KEK) or KMS/Vault key permissions | Unwraps every DEK. Loss of confidentiality exposes every vaulted credential. | Environment or KMS. Never in the database. |
| 2 | Vaulted target credentials and their DEKs | Direct access to every enrolled machine. | Database, as AES-256-GCM ciphertext plus wrapped DEK. |
| 3 | ASG role credentials (role ARN, ExternalId, temporary STS credentials) | Lets an attacker enumerate and, with Instance Connect, reach cloud instances. | Database (ARN, ExternalId encrypted); STS credentials in memory only. |
| 4 | Auth session tokens | Impersonate a logged-in user or admin without knowing their password. | Browser cookie; SHA-256 hash in database. |
| 5 | Session recordings | Contain everything typed and shown, including secrets users paste into shells. | Object storage or local disk, encrypted. |
| 6 | Audit log | Evidence for investigations and compliance. Tampering hides intrusions. | Database, hash-chained, with external anchors. |
| 7 | Policy and target configuration | Editing a policy grants access; editing a target address redirects a user to a hostile host. | Database. |
| 8 | User directory and MFA secrets | TOTP secrets allow MFA bypass; password hashes enable offline cracking. | Database, TOTP secrets encrypted, passwords hashed with Argon2id. |

## 3. Attacker profiles

| Profile | Access | Goal | Capability we assume |
|---|---|---|---|
| A1 Anonymous internet attacker | Reaches the public listener only | Get a foothold, harvest credentials, deny service | Automated scanning, credential stuffing, exploitation of web vulnerabilities |
| A2 Authenticated low-privilege user | Valid account with the `user` role | Reach targets outside their policy, read recordings, escalate to admin | Full API access as themselves, can craft arbitrary requests, can run code on targets they are allowed to reach |
| A3 Malicious or compromised admin | Valid `admin` role | Exfiltrate credentials, cover tracks, grant themselves durable access | Can change any configuration through the UI or API |
| A4 Compromised target host | Controls a machine that Zanskar connects to | Attack the gateway through the protocol channel, capture credentials, pivot to other targets | Sends malicious SSH, RDP, VNC or WinRM responses; presents forged host keys |
| A5 Compromised guacd | Code execution inside the sidecar | Read every RDP and VNC credential and session, attack the gateway | Full control of the guacd process and its network position |
| A6 Network attacker between gateway and target | Can observe or modify traffic on TB3 | Steal credentials, inject commands, redirect connections | Passive capture, active MITM, DNS or ARP manipulation |
| A7 Supply-chain attacker | Can influence a dependency, build, or release artifact | Ship a backdoor to every deployment | Publishes malicious module versions, compromises CI, or replaces release binaries |

## 4. Threats by trust boundary (STRIDE)

### TB1 Browser and gateway

| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Credential stuffing and password spraying against the login endpoint | Argon2id hashing, per-account and per-IP rate limiting, progressive lockout, mandatory MFA for admin and auditor, MFA available to all |
| Spoofing | Stolen session cookie reused from another machine | Opaque 256-bit random tokens stored hashed, `Secure`, `HttpOnly`, `SameSite=Strict`, absolute and idle expiry, binding to the originating IP range is optional per deployment |
| Spoofing | Phishing of TOTP codes | WebAuthn offered as phishing-resistant second factor; TOTP codes single-use with a short replay window |
| Tampering | Cross-site request forgery against state-changing endpoints | CSRF token on every non-GET request, `SameSite=Strict`, `Origin` header verification on WebSocket upgrade |
| Tampering | Cross-site scripting through target names, usernames, or terminal output | Strict Content Security Policy with no inline scripts, output encoding in the SPA, terminal rendering through xterm.js which does not interpret HTML |
| Repudiation | User denies having run a session | Every connect, disconnect, and input stream is recorded and linked to the authenticated user in the audit log |
| Information disclosure | Verbose errors reveal internal hostnames or stack traces | Generic error responses to the client, details only in server logs with a correlation ID |
| Information disclosure | Recording or credential data cached by the browser | `Cache-Control: no-store` on all API responses, recordings streamed with authorization on every request |
| Denial of service | WebSocket flood or slowloris on the listener | Connection limits per user, read and write deadlines, idle timeouts, upstream rate limiting recommended |
| Elevation of privilege | User calls an admin API directly | Authorization enforced in the handler layer for every route, never in the UI alone; roles resolved server-side from the session |

### TB2 Gateway and guacd

| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | A rogue process impersonates guacd and harvests credentials | guacd address is fixed in configuration; deployment guidance requires a private network or Unix socket; mutual TLS to guacd is a planned hardening item |
| Tampering | Malicious guacd injects input into a session | Accepted residual risk; guacd is inside the trusted zone and is isolated from everything except the gateway and targets |
| Information disclosure | guacd logs credentials | guacd log level set to warning or above; guacd runs read-only with a tmpfs |
| Denial of service | guacd exhaustion | Per-gateway cap on concurrent desktop sessions; guacd runs with resource limits |
| Elevation of privilege | guacd reaches the database or object storage | Network policy: guacd may only reach the gateway and target subnets |

### TB3 Gateway or guacd and targets

| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Attacker redirects the gateway to a hostile host that harvests credentials | SSH host key pinning: trust on first use during enrollment, admin must approve the fingerprint before users can connect, any later change blocks connections until re-approved. RDP: TLS certificate pinning with the same approval flow. VNC and WinRM: TLS required where the protocol supports it |
| Tampering | Active MITM injects commands into an SSH or RDP session | SSH provides integrity natively; RDP with TLS and NLA provides integrity; VNC without TLS is flagged as insecure in the UI and can be disabled by policy |
| Repudiation | Target claims the gateway never connected | Gateway logs every connection attempt with source, target, protocol, credential ID, and outcome |
| Information disclosure | Target-side capture of a passthrough credential | Inherent: the target must receive the credential. Prefer SSH certificates and Instance Connect where the box does not store a long-lived secret |
| Information disclosure | Compromised target returns malicious escape sequences that leak terminal state | xterm.js sanitization; the gateway never interprets terminal output |
| Denial of service | Target hangs the connection to tie up gateway resources | Connect timeout, keepalive, idle timeout per policy |
| Elevation of privilege | Compromised target exploits the SSH or RDP client implementation | SSH client is Go with memory safety; RDP and VNC are handled inside guacd, which is isolated per section 5 |

### TB4 Gateway and database

| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Attacker connects to the database with stolen application credentials | Database credentials are deployment secrets; TLS to PostgreSQL required outside loopback; least-privilege database role |
| Tampering | Attacker with database access edits policies or targets | Detected through the audit log; configuration changes always produce an audit event, and direct database writes produce a chain gap on verification |
| Tampering | Attacker with database access deletes or rewrites audit events | Hash chain; periodic anchors exported outside the database; `audit_events` has no UPDATE or DELETE grant for the application role |
| Information disclosure | Database dump exposes credentials | Every secret is AES-256-GCM ciphertext under a per-secret DEK; DEKs are wrapped by the KEK, which is never stored in the database |
| Information disclosure | SQL injection | Parameterized queries only through sqlc-generated code; no string-built SQL |
| Denial of service | Connection pool exhaustion | Bounded pool, statement timeouts |

### TB5 Gateway and object storage

| Category | Threat | Mitigation |
|---|---|---|
| Tampering | Recording modified after the fact | SHA-256 of each recording stored in the audit chain at session end; verification on playback |
| Information disclosure | Bucket misconfiguration exposes recordings | Recordings encrypted client-side by the gateway before upload; bucket policy guidance requires private ACLs and server-side encryption in addition |
| Repudiation | Auditor views a recording without a trace | Every playback request produces an audit event naming the auditor and the recording |

### TB6 Gateway and AWS APIs

| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Confused deputy: another tenant asks Zanskar to assume their role | Cross-account role requires an ExternalId generated by Zanskar per enrollment |
| Elevation of privilege | Over-broad role lets a compromised gateway alter infrastructure | Role policy limited to Describe calls plus optional `ec2-instance-connect:SendSSHPublicKey`; documented least-privilege policy shipped with the product |
| Information disclosure | STS credentials logged or persisted | Kept in memory, refreshed before expiry, never written to the database or logs |
| Denial of service | API throttling stalls the health poller | Exponential backoff; stale pool data is marked stale in the UI rather than silently reused |

### TB7 Gateway and identity providers

| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Forged OIDC token | Signature verification against the provider JWKS, issuer and audience checks, nonce and PKCE on the authorization code flow |
| Spoofing | LDAP injection in the bind or search filter | All user input escaped per RFC 4515; bind DN built from a template with escaped values |
| Information disclosure | LDAP bind credentials or client secret leaked | Stored as vaulted secrets under envelope encryption; LDAPS or StartTLS required |
| Tampering | Group membership manipulated at the provider to gain access | Accepted as out of scope: the provider is the source of truth. Group-to-role mapping is admin-controlled inside Zanskar and audited |

## 5. Controls we commit to

Each control below is a requirement, not an aspiration. A pull request that weakens one needs a
threat model update in the same change.

| Control | Detail | Threats addressed |
|---|---|---|
| Argon2id password hashing | Parameters at or above OWASP recommendation, per-user salt, constant-time comparison | A1 credential stuffing, offline cracking after a database leak |
| TOTP and WebAuthn MFA | Required for `admin` and `auditor`, available to `user`, enforceable by policy | A1, phishing |
| Envelope encryption | Per-secret DEK, AES-256-GCM, DEKs wrapped by a KEK from a local master key, AWS KMS, or Vault Transit. See ADR 0007 | Database leak, backup leak |
| Hash-chained audit log | SHA-256 chain over canonical JSON, append-only, external anchors. See ADR 0008 | A3 track covering, database tampering |
| Host key and certificate pinning | TOFU at enrollment, admin approval, change blocks connections | A4, A6 |
| guacd isolation | Private network or Unix socket, no route to the database, object storage or internet; read-only filesystem | A5 |
| Server-side policy evaluation | Evaluated at connect and re-evaluated on a timer during the session; a revoked policy terminates live sessions | A2 |
| Opaque hashed session tokens | 256-bit random, SHA-256 stored, never logged, rotated on privilege change | Token theft, database leak |
| Strict CSP and cookie flags | `default-src 'self'`, no inline scripts, `Secure`, `HttpOnly`, `SameSite=Strict` | XSS, CSRF, session theft |
| CSRF tokens | Double-submit token verified on every state-changing request, `Origin` check on WebSocket upgrade | CSRF |
| Rate limiting and lockout | Per-account and per-IP limits on login, MFA and connect; progressive lockout with admin unlock | A1 |
| No secrets in logs | Structured logging with a redaction layer; credentials, tokens, and MFA secrets are typed so they cannot be formatted by accident | Log leakage |
| Memory hygiene | Plaintext credentials held in byte slices that are zeroed after use; no plaintext in long-lived structs | Memory disclosure |
| Signed releases with SBOM | Binaries and images signed with cosign, SBOM published, dependency scanning in CI, `go mod verify` | A7 |

## 6. Residual risks

We state these plainly so that deployers can decide whether to accept them.

1. **A compromised admin can grant themselves access.** Admin privileges exist to configure access.
   Zanskar makes this visible through the insert-only, hash-chained audit log and logs every read of
   a recording, but it cannot stop an admin from adding themselves to a policy or from reading what
   they did. Mitigation is procedural: two-person review of admin actions, and the `auditor` role
   held by people who hold no `admin`.
2. **guacd is C code we do not own.** RDP and VNC parsing happens in a process we did not write. A
   memory safety bug there is a gateway compromise vector. We contain it with network isolation and
   a read-only container, and we track upstream security advisories.
3. **Passthrough credentials transit the gateway in memory.** When a user supplies their own
   credential at connect time, the gateway holds it in plaintext until the handshake completes. A
   memory-reading attacker on the gateway host would see it. We zero the buffer after use and
   never persist it.
4. **Recordings capture secrets users type.** A recording is as sensitive as the session was. We
   encrypt recordings and audit every view, but auditors can still see pasted secrets.
5. **VNC without TLS is not confidential.** We flag it in the UI and let policy forbid it, but we
   do not refuse it outright because many lab environments rely on it.
6. **Availability of the health pool depends on AWS API quotas.** Stale data is shown as stale.

## 7. Compliance mapping

This table maps Zanskar controls to common frameworks. It is a starting point for an auditor, not
an attestation.

| Control | SOC 2 | ISO 27001:2022 Annex A | PCI DSS 4.0 | NIST 800-53 r5 |
|---|---|---|---|---|
| Role-based access with separation of duties (admin, auditor, user) | CC6.1, CC6.3 | A.5.15, A.5.18, A.8.2 | 7.2, 7.3 | AC-2, AC-3, AC-6 |
| Policy-driven access to targets, re-evaluated during sessions | CC6.1, CC6.3 | A.5.15, A.8.3 | 7.2.1, 7.2.2 | AC-3, AC-6 |
| MFA for privileged roles, available to all | CC6.1 | A.5.17, A.8.5 | 8.4, 8.5 | IA-2(1), IA-2(2) |
| Argon2id password storage, lockout, password policy | CC6.1 | A.5.17 | 8.3.2, 8.3.4, 8.3.6 | IA-5 |
| Envelope-encrypted credential vault with key rotation | CC6.1, CC6.6 | A.5.16, A.8.24 | 8.6, 3.5 | IA-5, SC-12, SC-28 |
| Session recording with integrity hashes | CC7.2 | A.8.15 | 10.2, 10.3 | AU-2, AU-9 |
| Hash-chained, append-only audit log with external anchors | CC7.2, CC7.3 | A.8.15, A.8.16 | 10.2, 10.3.1, 10.3.2 | AU-2, AU-9, AU-10 |
| Audited viewing of recordings and audit data | CC6.3, CC7.2 | A.8.15 | 10.3.1 | AU-9(4) |
| TLS on every external connection, host key and certificate pinning | CC6.7 | A.8.20, A.8.24 | 4.2 | SC-8 |
| Session timeouts, idle timeouts, concurrent session limits | CC6.1 | A.8.5 | 8.2.8 | AC-11, AC-12 |
| Identity lifecycle via OIDC and LDAP with audited role mapping | CC6.2 | A.5.16, A.5.18 | 8.2 | AC-2, IA-2 |
| Signed builds, SBOM, dependency scanning | CC7.1, CC8.1 | A.8.8, A.8.29 | 6.3 | SA-11, SR-4 |

## 8. Review process

- Any change under `internal/auth`, `internal/policy`, `internal/crypto`, `internal/audit`, or
  `internal/gateway` requires a reviewer to check this document and update it if a boundary or
  control changed.
- The STRIDE tables are re-walked at every phase boundary of the roadmap.
- Findings from external testing are recorded in section 6 until resolved.
