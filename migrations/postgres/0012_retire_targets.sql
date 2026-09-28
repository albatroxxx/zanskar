-- Targets and autoscaling groups are retired, not erased (ADR 0019): the row
-- stays, so past sessions, recordings and audit events keep resolving to the
-- machine's name, while every listing and lookup filters on deleted_at. The
-- UNIQUE on name gives way to a partial unique index so a retired name can be
-- enrolled again.
ALTER TABLE targets ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE targets DROP CONSTRAINT targets_name_key;
CREATE UNIQUE INDEX targets_name_live_idx ON targets (name) WHERE deleted_at IS NULL;

ALTER TABLE autoscaling_groups ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE autoscaling_groups DROP CONSTRAINT autoscaling_groups_name_key;
CREATE UNIQUE INDEX autoscaling_groups_name_live_idx ON autoscaling_groups (name) WHERE deleted_at IS NULL;
