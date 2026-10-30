-- The legacy policy columns go, now that the data step (0036) has written
-- every policy's grants (ADR 0036); their indexes and the subject check go
-- with them. grants becomes NOT NULL: a row the data step has not converted
-- stops this migration rather than being dropped unconverted.
ALTER TABLE access_policies ALTER COLUMN grants SET NOT NULL;
ALTER TABLE access_policies ALTER COLUMN grants SET DEFAULT '[]';
ALTER TABLE access_policies
    DROP COLUMN group_id,
    DROP COLUMN user_id,
    DROP COLUMN target_selector,
    DROP COLUMN protocols,
    DROP COLUMN rules,
    DROP COLUMN time_windows,
    DROP COLUMN max_session_minutes,
    DROP COLUMN idle_timeout_minutes,
    DROP COLUMN retention_days,
    DROP COLUMN allow_clipboard,
    DROP COLUMN allow_file_transfer,
    DROP COLUMN require_mfa,
    DROP COLUMN require_approval;
