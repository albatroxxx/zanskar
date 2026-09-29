-- Recording retention per policy and per target (QA finding R12). Days to
-- keep a session's recording: the target's value wins over the policy's,
-- and a NULL leaves the global retention policy in charge. The value is
-- fixed on the recording (retention_until) when the session starts.
ALTER TABLE access_policies ADD COLUMN retention_days INTEGER;
ALTER TABLE targets ADD COLUMN retention_days INTEGER;
