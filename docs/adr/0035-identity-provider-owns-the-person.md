# 0035. A single sign-on provider owns the person: their second factor, their session, their joining and leaving

Date: 2026-10-30

## Status

Proposed. Amends the identity-provider behaviour first described in
[ADR 0005](0005-separate-identity-auth-from-target-credentials.md) and leaves the step-up rule of
[ADR 0027](0027-restricted-console-cli.md) as it is.

## Context

An operator connected a Keycloak realm made for Zanskar and reported three problems
(2026-10-30):

1. **People appeared only at their first sign-in.** Someone added to the realm had no account
   in Zanskar until they signed in, so an administrator could not put them in a group or
   write a policy for them beforehand. Someone removed from the realm kept their account, and
   any session they had stayed open up to the 12-hour session limit.
2. **Signing out did not sign out.** After signing out of Zanskar, "Sign in with Keycloak"
   came straight back without a password: Keycloak's own session was still alive, and only
   Zanskar's code step stood in the way.
3. **Two second factors.** Keycloak asked for its one-time code, then Zanskar asked the person
   to enrol an authenticator of its own. An OIDC provider was trusted with MFA only when an
   administrator ticked `skip_mfa`, which was off by default.

The operator's position: when a person comes from a provider, the provider is responsible for
their MFA, and Zanskar should follow the provider's directory. Groups are not wanted from it.

## Decision

**For people from a single sign-on (OIDC) provider, the provider decides who they are, how they
prove it and whether they still belong. Zanskar follows: it asks for no second factor of its own,
signs them out of the provider when they sign out, and can keep its accounts in line with the
provider's directory.**

- **Second factor.** An OIDC sign-in completes on the provider's word. Zanskar asks for no code
  and no enrolment, whatever `auth.require_mfa` says; that setting now covers local and LDAP
  accounts only. A provider that does no MFA of its own is marked `zanskar_mfa`, and its people
  get the Zanskar authenticator as before. `zanskar_mfa` replaces `skip_mfa` under a new name
  with the opposite default, so every configuration sealed before reads as "the provider owns
  MFA" without an edit. LDAP is not a provider in this sense: a bind checks a password and
  nothing else, so directory accounts keep the Zanskar authenticator.
- **Policies that require MFA** are met by an enrolled authenticator, or by an account that
  signs in only through a provider that owns MFA (an OIDC link, no local password, the provider
  enabled and not marked `zanskar_mfa`). Without this, every such person would be refused at
  connect.
- **Step-up is unchanged.** The console command line, host actions and the two settings that
  decide where a vaulted credential goes still ask for a Zanskar authenticator code (ADR 0027,
  0032). An administrator from a provider who needs them enrols one under Account. Proving a
  step-up through the provider (a fresh sign-in with `prompt=login`) is left for later.
- **Sign-out.** A session that signs in through an OIDC provider keeps the provider and the ID
  token it issued, sealed to that session (`auth_sessions.idp_id`, `id_token_enc`,
  `key_version`). Signing out revokes the session and answers with the provider's
  `end_session_endpoint` (OpenID Connect RP-Initiated Logout): `id_token_hint`, `client_id`,
  and, as `post_logout_redirect_uri`, the provider's own callback with `state=signed-out`, which
  sends the browser on to the sign-in page. The callback is registered at the provider already,
  or no sign-in would work; Keycloak 26 refuses any address it has not registered and then keeps
  its session, which is exactly the failure being fixed. `keep_provider_session` leaves the
  provider alone, for a realm other applications share. An endpoint that is not https, a deleted
  provider or an unreachable one, and a password session all sign out locally.
- **Directory sync.** `sync_users` lists the provider's directory every `sync_minutes` (5 to
  1440, default 15), and an administrator can run it at once. A Keycloak realm is listed
  through its admin API with the provider's own client: a client-credentials token for its
  service account, which needs the `realm-management` role `view-users` and nothing else. An
  LDAP directory is listed with the user filter's `%s` as a wildcard, in pages, as the bind
  account; an Active Directory account disabled there counts as gone. Other OIDC providers
  cannot be listed (OIDC has no user listing); Okta and Entra ID push users with SCIM, which
  would be a separate feature.
  - Each person listed is asserted exactly as their sign-in would be. Keycloak's ID token
    subject is the user's id; the username claim (`preferred_username` or `sub`; never email,
    which a username cannot hold) and the allowed-domain gate are the same code.
  - A person with no account gets one before any sign-in, by the first-sign-in rules: an
    administrator's pre-created password-less account is adopted, else one is created with the
    default roles when the provider creates accounts.
  - A person who leaves, or is disabled at the provider, has the account disabled and marked
    (`users.directory_removed_at`), and their browser and live sessions end. One who comes back
    is enabled again. An account an administrator disabled or locked is never touched, and an
    administrator's change of status clears the mark.
  - Only a complete listing is acted on. The Keycloak count is read before and after the pages,
    and a realm that changed in between fails the run. A listing of no one, or one that would
    disable more than half the provider's active accounts at once (and more than three), holds
    the removals back and says so; the administrator can apply them from the console. The last
    active administrator is never disabled.
  - Group memberships are not synced. Mapped groups still follow each sign-in.
- **Audit.** `user.logout` carries `provider_sign_out`. The sync records each change as
  `user.create`, `user.link` or `user.update` with `via: directory_sync`, and the run as
  `idp.sync` when it changed something, held something back, failed for a new reason, or an
  administrator asked for it; a quiet scheduled run writes nothing.

## Consequences

- People from the provider appear in Zanskar as they join the realm, and lose access within one
  interval of leaving it, instead of at the end of their session.
- Signing out of Zanskar signs the browser out of the provider, so the next sign-in asks for the
  provider's password and code. With a realm shared by other applications that is a sign-out
  from all of them, which is why `keep_provider_session` exists.
- MFA for provider accounts is as strong as the provider makes it. A deployment whose provider
  does not enforce MFA must mark it `zanskar_mfa`; the release notes say so, because for an
  installation that relied on the old default this is a change of posture.
- The ID token sits in the database for the session's life, sealed under the data key and bound
  to the session's id, and is deleted with the session. It travels once, in the sign-out URL, as
  the standard asks.
- A sync on several gateway instances at once is harmless but not coordinated: the second
  creation of an account is a conflict for that run, and the next run finds it linked.
