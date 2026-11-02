-- Access reviews (ADR 0040): when an administrator last went through who a
-- policy covers and kept or removed each, and who. NULL until the first
-- review. The decisions themselves are the policy.review audit event.
ALTER TABLE access_policies ADD COLUMN reviewed_at TEXT;
ALTER TABLE access_policies ADD COLUMN reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL;
