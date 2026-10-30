-- An access policy names many groups and users and holds grants, each with
-- its own conditions (ADR 0036). The subjects get a table, since ForUser
-- joins on them; each existing policy's one subject is copied into it. The
-- grants are a JSON column, NULL until the data step (0036) converts the
-- legacy columns, which 0037 then drops. Deleting a group or a user removes
-- it from its policies; the policy stays.
CREATE TABLE access_policy_subjects (
    policy_id  TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    group_id   TEXT REFERENCES groups(id) ON DELETE CASCADE,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    CHECK ((group_id IS NULL) <> (user_id IS NULL)),
    UNIQUE (policy_id, group_id),
    UNIQUE (policy_id, user_id)
);
CREATE INDEX access_policy_subjects_group_idx ON access_policy_subjects(group_id);
CREATE INDEX access_policy_subjects_user_idx ON access_policy_subjects(user_id);
INSERT INTO access_policy_subjects (policy_id, group_id, user_id) SELECT id, group_id, user_id FROM access_policies;
ALTER TABLE access_policies ADD COLUMN grants TEXT;
-- The grant whose cap a just-in-time request took; a grant is a JSON member
-- of its policy, so there is no foreign key.
ALTER TABLE access_requests ADD COLUMN grant_id TEXT;
