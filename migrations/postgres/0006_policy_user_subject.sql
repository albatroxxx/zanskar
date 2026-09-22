-- A policy may bind to one user instead of a group (ADR 0013): exactly one
-- of group_id and user_id is set. Existing rows keep their group.
ALTER TABLE access_policies ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE access_policies ALTER COLUMN group_id DROP NOT NULL;
ALTER TABLE access_policies ADD CONSTRAINT access_policies_subject CHECK ((group_id IS NULL) <> (user_id IS NULL));
CREATE INDEX access_policies_user_idx ON access_policies(user_id);
