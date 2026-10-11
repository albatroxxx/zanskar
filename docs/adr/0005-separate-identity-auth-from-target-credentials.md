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

## Addendum 2026-10-11: a provider adopts the account an administrator created

Only just-in-time provisioning ever tied an account to an identity provider. The first sign-in
created a user carrying the provider's id and the person's external id (the OIDC `sub`, the
LDAP `objectGUID` or `entryUUID`), and later sign-ins matched on that pair. An administrator
could create an account with no password for the purpose (`password_less` in the API, *Signs in
through an identity provider* in the console), but nothing ever linked it. With
auto-provisioning off the person was refused as not provisioned. With it on, the sign-in
collided with the username already there. And a directory username that differed created a
second account and left the first one unused.

The first sign-in now adopts such an account. When no user is linked to the external id, Zanskar
looks up the local account by the username the provider asserts, the one just-in-time
provisioning would create (case does not matter). If that account has no password and no
provider, it is linked to this provider and external id and nothing else about it changes: it
keeps the roles the administrator gave it, not the provider's default roles. Mapped groups,
display name and email then apply as at any sign-in. Later sign-ins match on the external id, so
a rename in the directory keeps the account. The link is recorded as an audit event of its own,
`user.link`, with the account as the actor and the provider and external id in the details,
ahead of the `user.login` it belongs to; the link stays even when the sign-in goes no further.

Refused whatever auto-provisioning says, and nothing is linked:

- An account with that username that has a password. A sign-in never takes over a local
  password account, the local admin kept for when the directory is down among them.
- An account already linked to another provider, or to a different subject at the same one (a
  directory account deleted and re-created gets a new `objectGUID`). A sign-in never moves an
  account between identities.
- A disabled or locked account.

An OIDC sign-in refused for one of the first two reasons ends on the sign-in page with
`account_conflict`, which is also the reason the audit log records. An LDAP one is the ordinary
refusal, with the reason in the server log. With no local account under that username,
auto-provisioning decides as before: on, a user is created with the default roles; off, the
sign-in is refused. Email and display name are never used to find an account, so a person the
directory calls `alice.smith` is not the pre-created `alice`.

The username a provider asserts is therefore what entitles someone to a pre-created account and
its roles. Use one the provider controls and people cannot choose for themselves:
`sAMAccountName` or `uid` from a directory, and on OIDC a claim the identity provider
administers rather than a self-service field. OIDC falls back to the part of the email before
the `@`, so a provider that admits accounts from outside the organisation needs allowed email
domains. Deleting a provider clears its accounts' link, so the next provider that asserts one
of their usernames adopts that account: when a new directory's usernames name different people,
remove the old accounts first. There is no API yet to link or unlink an account by hand.

## Addendum 2026-10-11: what a provider sign-in records, and LDAP group keys

A sign-in through a provider now reports what it changed, and the caller audits it, so access
granted through a provider is on the record like access an administrator grants:

- An account provisioned at sign-in is recorded as `user.create` with `via: identity_provider`,
  its roles, and `roles_granted` when the provider's default roles include admin or auditor
  (ADR 0006). Before, it left no trace but the `user.login`.
- Mapped group memberships the sign-in added or removed are recorded as `user.groups.sync`. A
  removal ends the live sessions the group granted, as an administrator's removal does (ADR 0013).
- Creating or changing a provider records the settings that decide who gets in and with what:
  default roles, auto-provisioning, group mapping, and for OIDC the issuer, allowed domains and
  the skip-MFA switch (before and after, on a change). Secrets are never part of it.

A group mapping key for LDAP may be the group's full DN, compared as LDAP compares DNs, or its
bare name. A bare name matches every group of that name in any OU, so it is only as safe as
control over group creation anywhere in the directory; the guide and the console recommend DNs.

