-- Two-phase rotation of an SSH certificate authority (ADR 0022): a prepared
-- next key, sealed separately, lives beside the signing key until an
-- administrator cuts over; the retired public key stays until the
-- administrator confirms it was removed from targets.
ALTER TABLE credentials ADD COLUMN pending_secret_enc BYTEA;
ALTER TABLE credentials ADD COLUMN pending_public_key TEXT;
ALTER TABLE credentials ADD COLUMN pending_key_version INTEGER REFERENCES key_versions(id);
ALTER TABLE credentials ADD COLUMN pending_created_at TIMESTAMPTZ;
ALTER TABLE credentials ADD COLUMN retired_public_key TEXT;
ALTER TABLE credentials ADD COLUMN retired_at TIMESTAMPTZ;
