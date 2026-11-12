-- Security keys and passkeys as a second factor beside the authenticator app
-- (ADR 0028). One row per registered key. A key is a plain row: it exists
-- until it is removed, so it has no status (ADR 0047). The public key is not
-- a secret and is stored as it is. The flags are kept as the browser reported
-- them: backup_eligible never changes for a key, backup_state says whether a
-- passkey is synced now, user_verified is latched once a PIN or fingerprint
-- was used. aaguid names the key's model, kept for an allow-list later.
CREATE TABLE webauthn_credentials (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    credential_id    BLOB NOT NULL UNIQUE,
    public_key       BLOB NOT NULL,
    sign_count       INTEGER NOT NULL DEFAULT 0,
    aaguid           BLOB,
    transports       TEXT NOT NULL DEFAULT '',
    backup_eligible  BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state     BOOLEAN NOT NULL DEFAULT FALSE,
    user_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    attestation_type TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL,
    last_used_at     TEXT
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials(user_id);
