# 0022. SSH certificate authority is the recommended way to reach Linux targets

Date: 2026-09-29

## Status

Accepted. Extends 0005 (identity authentication is separate from target credentials), which
introduced the `ssh_ca` credential type.

## Context

The v1.0 manual QA round asked for self-rotating target credentials (finding R8): a vaulted
SSH key stays valid on every host until an administrator replaces it by hand, so a leaked key
is useful for as long as nobody notices. The obvious answer, rotating static keys in two
phases, is a new subsystem with the worst failure modes in the product: the gateway would
write to every target's `authorized_keys`, half-rotated fleets would need reconciliation, and
a host that is down during a rotation would keep the retired key.

Zanskar has had a certificate-authority mode since Phase 2. An `ssh_ca` credential holds a CA
private key sealed by the key ring; at connect time the gateway mints a user certificate that
lives for minutes, signs in with it, and keeps nothing. Targets trust the authority's public
key through one `TrustedUserCAKeys` line. Nothing per target is stored on the gateway, in the
vault, or on the host, so there is nothing to rotate there. The mode was, however, a bare
credential type: the console required a pasted key even though the API could generate one,
nothing showed an administrator what to install on a target, every certificate lived exactly
five minutes, any login user could be named, and rotating the CA key was the same in-place
overwrite as for a password, which breaks every session on a host that has not yet learned
the new key.

## Decision

**Certificate-authority mode is the recommended path for Linux targets.** Static keys remain
supported as the fallback; no rotation of static keys will be built. Passwords for RDP, WinRM,
VNC and database targets stay vaulted and are not rotated by Zanskar: the systems that own
them (LAPS or managed service accounts for Windows, IAM authentication or the provider's
rotation for cloud databases) do that better, and Zanskar shows a password's age and makes
replacing it a single step.

The mode is completed as follows:

- **The console generates the authority.** Creating an `ssh_ca` credential generates an
  ed25519 key by default; the private half is sealed and never shown. The console shows the
  public key and the exact commands that make a target trust it, after creation and from a
  setup panel on the credential.
- **One principal per certificate.** A session certificate is valid for exactly one login
  user: the credential's username when it names one, otherwise the Zanskar username of the
  person connecting, so each person reaches the target as themselves. The certificate permits
  a PTY and nothing else, carries a lifetime set on the credential (`certificate_ttl_seconds`,
  default 300, 60 to 3600), and a key id `zanskar:<zanskar user>:<login user>:<unix time>`,
  which sshd prints on every accepted login so the target's own log ties the login to a
  Zanskar identity.
- **An allowlist of principals.** A credential may list the login users it issues
  certificates for (`certificate_principals`). A connect for any other login user is refused
  before a ticket is issued with the code `login_user_not_permitted`, audited as a failed
  `session.connect` with that reason. An empty list permits any login user. The allowlist is
  checked against the login user, so with a blank username it constrains which Zanskar users
  the credential serves.
- **Rotation of the CA key is two-phase and administrator-gated**, never a timer: prepare a
  next key and publish both public keys, cut over once targets trust the new one, then retire
  the old public key from targets. The in-place `rotate` stays for the other credential
  types. The rotation flow and a probe that confirms a target accepts certificates follow in
  the next change; this decision fixes their shape.

## Consequences

- The credential lifecycle Zanskar owns is the CA key, one secret per fleet, instead of one
  key per host. Rotating it is a console operation plus a line on each target, with sshd
  accepting both keys during the overlap.
- Targets need one configuration change once: `TrustedUserCAKeys` in `sshd_config` (or user
  data for autoscaling groups, as 0011 already allows). The console prints the commands.
- The target's auth log gains the Zanskar username for every login, which the static-key path
  cannot offer.
- `certificate_ttl_seconds` and `certificate_principals` were already in the OpenAPI
  description with no implementation; the implementation takes those names, with the default
  corrected to 300 seconds and the ceiling to 3600, because a certificate only has to outlive
  the handshake.
- Windows and database credentials are unchanged. Their rotation is explicitly out of scope.
