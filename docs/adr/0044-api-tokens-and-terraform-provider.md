# 0044. API tokens for automation, and a Terraform provider over them

Date: 2026-11-03

## Status

Accepted 2026-11-03. The owner asked for everything the 2026-11-03 live audit recommended that
1.15.0 left out; this is the second half of its idea 10 ("config as code: YAML export/import or a
Terraform provider"). ADR 0043 built the YAML file; it named the provider a separate project.

## Context

A Terraform provider, or any pipeline, needs to call the API without a person at a browser: no
password typed, no authenticator code, no cookie to carry a CSRF token. Zanskar's only bearer
credential was a provider's SCIM token, which reaches the SCIM routes alone. Giving automation a
password account would mean a standing account without a second factor and a sign-in flow
scripted around it.

## Decision

1. **An API token is an administrator, on the configuration API only.** An administrator makes
   one under Settings › API tokens: a name and a life (1 to 365 days, 90 by default). It is
   `zapi_` and 32 random bytes, shown once; the gateway keeps its SHA-256 and its first 12
   characters to tell it apart. `Authorization: Bearer zapi_...` is that administrator, on these
   routes: `GET /auth/me`; groups and targets, read and written; access policies by id, read and
   written, never their reviews (a review is a person's evidence); credentials, read only, so no
   secret passes through a token or lands in a Terraform state; the configuration file's export
   and import. Anything else is `403 token_scope`; a WebSocket is never reached.
2. **It stands only while its owner does.** Each request checks the token (not revoked, not
   expired, compared in Go so both engines agree) and its owner: deleted, blocked, or no longer an
   administrator, and it is `401 invalid_token`. A token sent with a cookie is the whole
   identity; a wrong one is refused, never read as the cookie. Other bearer tokens (SCIM's
   `zscim_`) are left to their routes.
3. **Made with a second factor, used without one.** A token acts without a code, so making one
   asks an administrator who has an authenticator for a code from the last 5 minutes, as host
   actions and approvals do. A token cannot make a token. At most 20 active tokens an
   administrator. Nothing that asks for a recent code is reachable with a token.
4. **On the record.** Making and revoking are audited (`api_token.create`, `api_token.revoke`,
   never the secret). A change made with a token is audited as its owner, with `api_token`
   naming the token. A token's last use is kept, written at most once a minute.
5. **A Terraform provider over the same API**, in the repository at
   `terraform-provider-zanskar/`, a Go module of its own so the gateway's binary, its notices and
   its vulnerability scan are not the provider's: resources `zanskar_group`, `zanskar_target` (a
   host, a database or an application, as the API has them) and `zanskar_access_policy`, and data
   sources `zanskar_credential` and `zanskar_group` that find an id by name. Credentials stay in
   the console's vault: a target names them by id, looked up by name, so no secret is in a plan
   or a state. A resource changed in the console shows as drift on the next plan; one deleted
   there is planned again.

## Consequences

- A leaked token is an administrator on the configuration API until it is revoked or lapses;
  its prefix lets a secret scanner find it, and the list shows when it was last used.
- Publishing the provider to the Terraform Registry needs a public repository named
  `terraform-provider-zanskar` and a signing key; until then it is built from this repository and
  installed with a `dev_overrides` or filesystem-mirror block (the guide says how).
- Users and group membership are the identity provider's (ADR 0035), not the provider's: a
  policy names a group or user by id, which the data sources look up.
