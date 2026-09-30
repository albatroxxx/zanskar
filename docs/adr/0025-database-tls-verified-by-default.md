# 0025. Database targets verify TLS by default; the master key can live in its own file

Date: 2026-09-30

## Status

Accepted. Amends 0017 (database access), which made unverified TLS (`prefer`) the default,
and extends 0007 (envelope encryption) on where the master key is read from.

## Context

A database session reaches the database through a sidecar that holds the credential (0017).
Since 1.2 a database target names how that sidecar protects its connection: `disable`,
`prefer`, `require` or `verify-full`, with a CA bundle for the last. The default was
`prefer`: encrypt when the server offers TLS, check nothing.

That default protects against someone reading the traffic, not against someone answering
in the database's place. Anyone who can intercept the connection between the gateway and
the database can present their own certificate, receive the vaulted credential in the
sign-in, and hold it. For a gateway whose purpose is to keep credentials out of reach, the
default must be the safe mode, with the weaker ones a visible, deliberate choice. The
OpenSSF Best Practices criterion `crypto_certificate_verification` says the same: TLS is
verified by default.

Separately, the master key could only come from `ZANSKAR_MASTER_KEY`, which in practice sits
in `/etc/zanskar/env` beside every other setting. Anything that prints or ships that file
(a support bundle, a configuration-management diff, a debugging `env`) carries the key with
it, and replacing the key means editing the settings file. `crypto_credential_agility` asks
for keys to be storable in files of their own, replaceable without touching the rest.

## Decision

**Database TLS.**

- A new database target that names no `tls_mode` gets `verify-full`. `verify-full` needs the
  CA bundle that signs the database's certificate (the sidecars verify against it and
  nothing else), so creating a target with neither is refused with a message that names the
  bundle to use (for Amazon RDS, the region's bundle) and says how to opt out.
- `require` and `prefer` stay available. The console lists them as *Encrypted, not
  verified* and *Encrypted if offered, not verified*, and marks such targets with a
  warning, so the choice is explicit and visible.
- Existing targets keep exactly what they had. Migration 0025 writes `prefer` into every
  database target stored without a mode, the value they already used, so an upgrade changes
  no connection.
- At session time, a missing or unknown mode fails closed to `verify-full` rather than open
  to `prefer`. After the migration no stored target lacks a mode; this guards the gap.

**Master key file.**

- `ZANSKAR_MASTER_KEY_FILE` names a file holding the base64 key. Setting it and
  `ZANSKAR_MASTER_KEY` together is refused.
- The file must be a regular file that only its owner can read or write (mode `0400` or
  `0600`); otherwise the gateway refuses to start, since a key readable by other local
  accounts is a key those accounts hold.
- `zanskar key rotate-master` rewraps the key ring and then replaces the file's contents
  atomically, keeping its owner and mode. It refuses `-env-file` when the key comes from a
  file.
- The Settings page says where the key was read from, never the key.

## Consequences

- An API client that creates a database target without `tls_mode` now gets a 400 unless it
  sends `tls_ca`. That is the point, and the release notes say so.
- An Amazon RDS target needs the regional CA bundle pasted in once. The global bundle
  (about 170 KB) is larger than the 64 KB a target accepts; the regional one is about 5 KB.
- `ZANSKAR_MASTER_KEY` in the environment file keeps working unchanged; the key file is an
  option, not a migration. `zanskar init` still writes the key into the environment file.
