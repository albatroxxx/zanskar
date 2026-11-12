# 0028. Security keys and passkeys as a second factor (WebAuthn)

Date: 2026-10-06

## Status

Accepted on 2026-10-06; build parked until the project owner resumed it on 2026-11-12. Amended
the same day, before the build: the gateway grew in the five weeks it waited, and the
[amendment](#amendment-2026-11-12-what-changed-before-the-build) at the end replaces what no
longer holds. Where the two differ, the amendment holds.

## Context

Every Zanskar account that uses a second factor uses an authenticator app (TOTP). Since 1.3.0
each code works once, so a code read over a shoulder cannot be replayed. A code can still be
**phished in real time**: a fake sign-in page asks for the password and the current code and
passes both to the real gateway within the same 30 seconds. The threat model lists this as open,
and WebAuthn as the planned answer. Administrators matter most here: one phished admin sign-in
reaches every target and, through the console command line, every setting.

WebAuthn (security keys such as a YubiKey, and passkeys in a phone, laptop or password manager)
closes that gap. The browser signs a challenge with a key that never leaves the authenticator,
and the signature names the web address the browser was really on. A look-alike site gets a
signature for the wrong address, which the gateway refuses. Nothing typed can be relayed.

Two facts about WebAuthn shape the decision:

- **It is bound to a host name.** A credential belongs to a domain (the "relying party ID") and
  can never be used for another. An IP address cannot be one. Changing the gateway's host name
  later makes every registered key unusable there.
- **It needs a trusted HTTPS page.** Browsers offer WebAuthn only in a secure context and refuse
  it on a page with a certificate error (Chrome does), which is what a fresh install shows until
  a real certificate is uploaded.

Zanskar today has no setting for its own public address. The OIDC handler has room for one
(`BaseURL`) but nothing sets it, so it builds its callback from the request's `Host` header.

Alternatives considered:

- **Keep TOTP only.** Simplest, but leaves real-time phishing open, which is the threat that
  matters for administrators.
- **Passwordless first (a passkey replaces the password).** The bigger usability win, but it
  changes the sign-in flow, lockouts, rate limits and the audit stages all at once, and it makes
  the passkey the only thing between an attacker and the account. Better as a later, separate
  decision once keys are in use as a second factor.
- **Write the WebAuthn verification ourselves.** It means parsing CBOR, COSE keys and attestation
  formats from untrusted input, which is where WebAuthn implementations have had their bugs. Not
  worth owning.
- **Require security keys for everyone at once.** Many installs have no trusted host name yet
  (see above), and users need time to get keys. It has to be possible, not forced.

## Decision

Zanskar accepts **WebAuthn as a second factor beside TOTP**. The password stays the first step.
At the second step the browser offers the user's security key or passkey if they have one, and
the authenticator code otherwise; either completes sign-in. An account may have an
authenticator app, one or more keys, or both. Verification uses the
[go-webauthn](https://github.com/go-webauthn/webauthn) library (BSD-3-Clause), not our own code.

**The public address is a boot setting.** A new `ZANSKAR_PUBLIC_URL` (for example
`https://zanskar.example.com`) names the address users open. Its host name is the relying party
ID and the full origin is what every signature must name exactly; neither is ever taken from the
request. It is set in the environment file, not on the Settings page, because changing it
orphans every registered key and must not be one click away. When it is unset, or is an IP
address, WebAuthn is off and the console says why; TOTP works as before. The OIDC handler uses
the same setting for its callback when it is set, instead of trusting `Host`.

**What counts as "has an authenticator".** Everywhere Zanskar asks that question it means "an
authenticator app or at least one key": the *Require an authenticator* setting, enrolment at
first sign-in, the policy switch *Require an enrolled authenticator*, single sign-on accounts
that must complete a second factor, and the console command line. A key proves a session's
second factor exactly as a code does, so the command line opens with a key touch as well as a
code. An administrator's *Reset authenticator* removes the app and every key.

**Keys and recovery**

- A user registers keys from their profile, names each one ("YubiKey 5C", "Work laptop"), sees
  when each was last used, and removes any of them. Up to ten per user.
- Recovery codes are issued once, when a user sets up their first second factor of any kind, app
  or key, and work the same way for both. A user with only keys is never left without a way back.
- Registering or removing a key needs a second factor proved in the last few minutes, as the
  command line does, so a stolen session cannot quietly add an attacker's key.

**How strictly a key is checked**

- **User verification preferred**, not required: a PIN or fingerprint on the key is used when it
  has one. The password was already the first factor.
- **Signature counter checked.** A counter that goes backwards suggests a cloned key; the
  sign-in is refused and audited as such.
- **No attestation.** Zanskar does not ask who made the key, which keeps any key or passkey
  usable and avoids collecting device details. The key's model id (AAGUID) is stored so an
  allow-list can be added later without re-registering.
- **Passkeys allowed.** Keys may be synced passkeys; whether a key is synced is stored and shown,
  for the admin requirement below.
- Public keys are stored as they are, not sealed under the master key: they are not secrets, and
  someone who can write the database can already sign in by other means. The challenge for each
  ceremony lives in memory for two minutes, belongs to one (partial) session, and works once,
  like the command line's state; high availability will move it to the database.

**Administrators** *(for approval: in or out of this first version)*

- A runtime setting, *Administrators must use a security key*, off by default. When on, an admin
  who has a key can no longer complete sign-in or open the command line with a code, only with
  the key; an admin without one is asked to register one at next sign-in. Recovery codes still
  work, and their use is audited.

**Audit and plain words.** New events: a key registered, renamed and removed, and the second
factor passed or failed with its method (`totp`, `webauthn`, `recovery`), including a counter
that went backwards. Each reads as a sentence on the Events page.

**Not in this version:** passwordless sign-in, attestation allow-lists, and keys for the console's
host commands.

## Consequences

- Real-time phishing of a second factor stops working for anyone who signs in with a key. The
  threat model's phishing row moves from planned to built for those accounts, with TOTP still
  open to relay for those who keep using it.
- Installs need a host name and a trusted certificate to use keys. An IP-only install, or one
  still on its first self-signed certificate, keeps TOTP only. The install guide and the
  troubleshooting page have to say so plainly, and the first-visit TLS step gains a reason to
  upload a real certificate.
- `ZANSKAR_PUBLIC_URL` is a new boot setting. Changing the host name later means every user
  registers their keys again; the docs say so where the setting is described.
- One new dependency with its own small tree (CBOR, COSE and attestation parsing). It goes
  through govulncheck, OSV, the SBOM and the third-party notices like every other.
- The command line's unlock and the "has an authenticator" checks change shape: they take a
  method and a proof, not only a 6-digit code. Existing API clients that send a code keep
  working.
- New storage: a table of registered keys per user, and recovery codes no longer tied only to
  the authenticator app. Two migrations, one per database, as usual.
- Testing: the Go side is tested with a software authenticator that produces real signatures,
  including a wrong origin, a reused challenge and a counter going backwards. The console is
  tested end to end in headless Chrome with its built-in virtual authenticator, the same way the
  screenshot tooling drives Chrome. Feature-test tickets on the board cover a hardware key and a
  phone passkey.
- Later, separately: passwordless sign-in with passkeys, and an allow-list of key models for
  organisations that want one.

## Amendment (2026-11-12): what changed before the build

The owner resumed this ADR on 2026-11-12 and took the recommended scope ("go ahead, update the
ADR first"). This section brings the decision up to the gateway as it is now and settles what the
build would otherwise decide by accident. Three points are marked *(owner to confirm)*; nothing is
built until they are.

### The public address already exists

`ZANSKAR_PUBLIC_URL` arrived on 2026-10-13 (#211) for single sign-on: an https origin with no
path, read at boot, and also the base of SCIM and notification links. WebAuthn reuses it and adds
no setting. Its host is the relying party ID and its origin is what every signature must name;
neither comes from the request. The boot check accepts an IP host, so "keys are off" (unset, or
an IP) is a state the console shows, not a boot error. This replaces the context paragraph that
says Zanskar has no setting for its address, the decision paragraph that introduces one, and the
consequence that calls it new.

### Three places take a proof, and a key works at each

A second factor is proved at three endpoints, and each writes the same proof, the session's
`mfa_verified_at` (`Sessions.MarkMFAProved`):

- **Sign-in**, `POST /auth/mfa/totp/verify`: a partial session becomes full.
- **Step-up**, `POST /auth/mfa/step-up`: every action that asks for a recent code reads the proof
  through `Principal.StepUpFresh()` (five minutes): the settings that decide where a credential is
  sent, approving access while *Approving asks for a code* is on, host actions and updates, boot
  setting changes, and making an API token.
- **The command line**, `POST /admin/cli/unlock` (fifteen minutes, sliding), and its commands that
  ask for a code from the last five minutes.

Each gains a key beside the code: a *begin* call returns a challenge bound to the session and the
purpose, and the *finish* call verifies the signature and writes the same proof. No action that
reads the proof changes. A failed key counts against the same limits as a wrong code: the
per-session step-up limiter (`MFAAttempts`, then closed for `LockFor`), the command line's five,
and at sign-in the end of the pending session. "Keys for the console's host commands", listed
above as not in this version, is therefore no gap: host actions read the step-up proof.

### Accounts with keys and no app

Step-up answers `409 mfa_not_enrolled` today to an account without an authenticator app. An
account with at least one key steps up with it.

*(owner to confirm)* **Accounts whose provider owns the second factor** (ADR 0035) may register
keys too. Their keys serve step-ups and the command line only; sign-in asks for one only when the
provider has *Also ask for a Zanskar authenticator* on, as it does for the app now. Without this,
an administrator who signs in through such a provider has nothing to prove a step-up with.

### Recovery codes

*(owner to confirm)* The codes keep their table (`mfa_recovery_codes`) and change when they are
issued:

- Once, when an account gets its first second factor of any kind: an app confirmed, or a first
  key registered, while it has neither. Confirming an app issues new codes every time today; that
  holds only for the first factor now.
- Adding a key, or an app beside keys, keeps the codes the account has.
- *New recovery codes* in the account dialog replaces them, behind a fresh second factor; the old
  ones stop working at once.
- An administrator's *Reset authenticator* removes the app, every key and every code, and the
  account enrols again at its next sign-in.

### What "has a second factor" means, everywhere

`idp.SecondFactor(users, providers, enrolled)`, wired in `cmd/zanskar/main.go` with
`totp.Enrolled`, takes "an app confirmed, or at least one key" instead. Its readers change with it,
and the build checks each one: the *Require an authenticator* sign-in gate and its enrolment step,
a grant's *Authenticator* condition, the command line's `mfa_enrolled`, the security-posture tile
*No authenticator yet* and its `postureWhere` filter, and *Also ask for a Zanskar authenticator* on
a provider.

### Lifecycles (ADR 0047)

*(owner to confirm)* A key is a plain row: it exists until it is removed, has no `status`, and is
not declared with `internal/states`. The account's *authenticator* lifecycle (`mfa_totp`: none,
enrolling, confirmed) stays the app's. What an account has as a second factor (none, app, keys,
both) is derived where it is shown and never stored. `docs/lifecycles.md` gains no lifecycle, only
a note under *authenticator* that keys count beside it, and the session lifecycle's note on
`mfa_verified_at` reads "a code typed or a key touched".

### Where people see it

- **The account dialog** (the username in the sidebar) lists the account's keys: name, when added
  and last used, and whether it is a synced passkey. *Add key*, *Rename*, *Remove*, and *New
  recovery codes*.
- **One second-factor control** at sign-in and at every code prompt (Settings, Approvals, host
  actions, API tokens, the command line): *Use your key* when the account has one and the address
  allows it, and the code field. Where keys cannot work (no public address, or an IP), the button
  is disabled with its reason on hover; no paragraph explains it.
- **The Users page**: *Reset authenticator* removes the app, every key and every recovery code; the
  page shows no per-person count of keys.

### Administrators must use a security key

In this version, off by default, as described above: the owner's go of 2026-11-12 took the
recommendation. It is a runtime setting under *Sign-in*, beside *Require an authenticator*.

### Not in this version

This replaces the list above: passwordless sign-in; an allow-list of key models; a rule against
synced passkeys (the synced flag is stored, so it can come later without re-registering).

### Facts pinned for the build

- [go-webauthn](https://github.com/go-webauthn/webauthn) v0.18.2 (2026-09-19, needs Go 1.26; the
  gateway builds with 1.27.4) is still the latest release.
- Migration 0055, in both engines: `webauthn_credentials` (id, user_id, name, credential_id
  unique, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, created_at,
  last_used_at).
- The OpenAPI document gains the begin and finish pairs and the key routes. The Terraform provider
  is untouched: a key belongs to a person, not to the configuration.
- `docs/threat-model.md`'s phishing row moves to built, for accounts that sign in with a key.
