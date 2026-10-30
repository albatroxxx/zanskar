-- ADR 0035. A session that signed in through an identity provider remembers
-- it, with the ID token the provider issued, sealed: signing out of Zanskar
-- ends the provider's session too, and the token is the id_token_hint that
-- lets the provider do so without asking.
ALTER TABLE auth_sessions ADD COLUMN idp_id TEXT REFERENCES identity_providers(id) ON DELETE SET NULL;
ALTER TABLE auth_sessions ADD COLUMN id_token_enc BLOB;
ALTER TABLE auth_sessions ADD COLUMN key_version INTEGER REFERENCES key_versions(id);
-- When the directory sync disabled the account because the person left the
-- directory. Only such an account is enabled again when they come back; one
-- an administrator disabled stays as the administrator left it.
ALTER TABLE users ADD COLUMN directory_removed_at TEXT;
