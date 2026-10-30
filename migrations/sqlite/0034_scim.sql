-- ADR 0035, amended: a provider can push its people to Zanskar over SCIM
-- 2.0, the standard Okta, Entra ID, OneLogin, JumpCloud, PingOne and
-- Authentik speak. The provider authenticates with a bearer token Zanskar
-- generated; only its SHA-256 is kept, like a session token's.
ALTER TABLE identity_providers ADD COLUMN scim_token_hash TEXT;
ALTER TABLE identity_providers ADD COLUMN scim_token_created_at TEXT;
-- The provider's own id for the person (SCIM externalId), which it may look
-- an account up by. It is not the sign-in subject: Entra ID's subject is
-- made per application, so the two never meet; the username is the key.
ALTER TABLE users ADD COLUMN scim_external_id TEXT;
-- When the provider deleted the account over SCIM. The account stays, with
-- its history, disabled; SCIM answers 404 for it from then on, and a later
-- creation of the same username takes it back.
ALTER TABLE users ADD COLUMN scim_deleted_at TEXT;
