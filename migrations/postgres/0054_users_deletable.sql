-- An account can be deleted whatever it did (ADR 0046, which replaces the
-- reasoning of ADR 0019 for people). A session and a recording view named the
-- user with ON DELETE RESTRICT, so an account that had ever connected could
-- only be disabled. They now keep who it was the way audit_events does: the
-- id as plain text, with no foreign key, and the username and display name as
-- they were, copied in when the row is written. Readers show the live name
-- while the account exists and the copy once it is gone.
ALTER TABLE access_sessions DROP CONSTRAINT access_sessions_user_id_fkey;
ALTER TABLE access_sessions ADD COLUMN user_username TEXT NOT NULL DEFAULT '';
ALTER TABLE access_sessions ADD COLUMN user_display_name TEXT NOT NULL DEFAULT '';
UPDATE access_sessions s SET user_username = u.username, user_display_name = u.display_name FROM users u WHERE u.id = s.user_id;

ALTER TABLE recording_views DROP CONSTRAINT recording_views_user_id_fkey;
ALTER TABLE recording_views ADD COLUMN user_username TEXT NOT NULL DEFAULT '';
ALTER TABLE recording_views ADD COLUMN user_display_name TEXT NOT NULL DEFAULT '';
UPDATE recording_views v SET user_username = u.username, user_display_name = u.display_name FROM users u WHERE u.id = v.user_id;
