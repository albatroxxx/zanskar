-- Why a session ended, in words (2026-11-03 live audit, Q7): what the
-- gateway told the person, or what the target's side said when it was the one
-- that ended it. NULL for every session before this and for a plain exit.
ALTER TABLE access_sessions ADD COLUMN end_detail TEXT;
-- A recording of a session that never drew a frame (Q6): its file is deleted
-- when the session ends and its row kept, so the session.start event that
-- names it still resolves; purged_at is set beside it, and lists leave it out.
ALTER TABLE recordings ADD COLUMN discarded_at TIMESTAMPTZ;
