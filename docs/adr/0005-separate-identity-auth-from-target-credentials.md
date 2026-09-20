# 0005. Separate identity authentication from target credentials

Date: 2026-09-20

## Status

Accepted

## Context

There are two distinct questions when a user connects to a machine: who is this person, and what
does the machine accept as proof that the connection is allowed. Many access tools conflate them,
which leads to designs where a user's directory password is forwarded to every target, or where
target credentials are tied to a login method.

## Decision

Zanskar keeps two independent subsystems.

**Identity authentication** answers who the user is. Providers are local accounts with Argon2id
password hashes, OIDC, and LDAP or Active Directory. MFA (TOTP, WebAuthn) attaches to the
identity, not to the target. The result is a Zanskar session with a set of roles and group
memberships.

**Target credentials** answer how the gateway authenticates to a box. A credential has a type
(password, SSH private key, SSH certificate authority, domain account, EC2 Instance Connect) and
one of three modes:

- `vaulted`: the secret is stored under envelope encryption and the user never sees it. This is
  the default and the only mode that supports non-repudiation of the target-side identity.
- `user_supplied`: the user is prompted at connect time. The gateway uses the secret for the
  handshake and discards it. Nothing is stored.
- `passthrough`: the user's own directory credential, captured at Zanskar login with explicit
  consent, is forwarded to domain-joined targets. Held in memory for the session, never persisted.

Access policies bind groups to targets and name which credentials may be used. A user can be
allowed to reach a target only with a specific vaulted credential, or only with their own
passthrough credential, and the policy is what decides.

## Consequences

- Adding an identity provider never touches target credential code, and vice versa.
- Vaulted credentials enable shared service accounts with per-user accountability through the
  audit log, which is the core PAM use case.
- Passthrough is convenient for Active Directory shops but is the least secure mode. It is off by
  default and requires an admin to enable it per policy.
- The data model has separate `identity_providers`, `users`, `credentials`, and
  `target_credentials` tables, and the policy engine references credential IDs explicitly.
