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

Amended 2026-09-28, to match what shipped and to add the rotation the first manual install round
found missing. As built, `key_versions` holds **DEK versions**, each wrapped under the single
configured KEK (the `local` master key today), and every secret row carries the DEK version that
sealed it. Two rotations exist, both as CLI commands:

- `zanskar key rotate` creates a new DEK version and makes it active. Secrets stored from then on
  are sealed under it; earlier rows stay under their version, which stays loaded for decryption.
  `zanskar key status` shows how many rows each version still protects.
- `zanskar key rotate-master` re-wraps every non-retired DEK under a new master key in one
  transaction, verifying each new wrapping before commit, and optionally rewrites the
  `ZANSKAR_MASTER_KEY` line of the service's environment file. Secret ciphertext is untouched, so
  the operation is a handful of rows however many secrets exist. A master key that leaked on its
  own is useless once this has run. A database that leaked together with the key is a different
  incident: the DEKs, and so the secrets, were exposed, and only rotating those secrets at their
  targets remedies it; the command says so.

The CSRF and OIDC-state keys are derived from the master key, so a rotation invalidates open
browser tabs' CSRF tokens (a reload recovers) and sign-ins in flight; user sessions are database
rows and survive. Background re-wrapping and automatic retirement of unreferenced versions remain
future work.

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
