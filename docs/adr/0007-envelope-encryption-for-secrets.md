# 0007. Envelope encryption for secrets

Date: 2026-09-20

## Status

Accepted

## Context

Zanskar stores target credentials, TOTP secrets, LDAP bind passwords, OIDC client secrets and ASG
ExternalIds. A database dump or backup must not expose them. Key rotation must be possible without
re-encrypting every secret, and deployments range from a laptop to an enterprise with a hardware
key management service.

Alternatives considered:

- **One symmetric key for everything.** Simple, but rotation means re-encrypting every row, and a
  single nonce mistake compromises everything.
- **Encrypt at the database level only.** Protects the disk, not the dump, and the application role
  still sees plaintext.
- **Require an external KMS.** Excellent security, unusable for evaluation.

## Decision

Every secret is encrypted with its own data encryption key (DEK) using AES-256-GCM with a random
96-bit nonce. The DEK is wrapped by a key encryption key (KEK) and stored alongside the ciphertext.
The KEK never enters the database.

KEK providers, selected by configuration:

- `local`: a 32-byte master key from the environment or a file with mode 0400. For development and
  small deployments.
- `awskms`: a KMS key; wrapping uses `Encrypt` and `Decrypt` with an encryption context that binds
  the DEK to the secret's identity.
- `vault`: HashiCorp Vault Transit engine.

A `key_versions` table records each KEK version with its provider identifier and creation time.
Every wrapped DEK references the KEK version that wrapped it. Rotation creates a new KEK version and
re-wraps each DEK under it in the background; the secret ciphertext is untouched. Old versions are
retained until no DEK references them, then marked retired.

The GCM additional authenticated data for each secret is its table name and row ID, so a
ciphertext moved to another row fails to decrypt.

Plaintext lives in a byte slice that is zeroed immediately after use. Types that hold plaintext
implement a `String()` method that returns `[redacted]` so that they cannot be logged by accident.

## Consequences

- A database dump without the KEK is useless to an attacker.
- Rotation is cheap and does not require downtime.
- Two extra columns per secret (wrapped DEK, KEK version) and one small table.
- The master key for the `local` provider is a single point of failure. Operators must back it up
  separately from the database, and the documentation says so on the first page.
