# 0028. Security keys and passkeys as a second factor (WebAuthn)

Date: 2026-10-06

## Status

Accepted on 2026-10-06; build parked until the project owner resumes it.

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
