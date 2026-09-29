-- Local-user onboarding (QA finding R25): a password an administrator set
-- or generated must be replaced by the user at their first sign-in, before
-- the second factor and before anything else.
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
