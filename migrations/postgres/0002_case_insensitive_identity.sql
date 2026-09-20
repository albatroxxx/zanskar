-- Usernames and emails are unique regardless of case.
CREATE UNIQUE INDEX users_username_lower_idx ON users (LOWER(username));
CREATE UNIQUE INDEX users_email_lower_idx ON users (LOWER(email)) WHERE email IS NOT NULL;

-- Encrypted columns record which key version sealed them (ADR 0007).
ALTER TABLE mfa_totp ADD COLUMN key_version INTEGER REFERENCES key_versions(id);
ALTER TABLE identity_providers ADD COLUMN key_version INTEGER REFERENCES key_versions(id);
