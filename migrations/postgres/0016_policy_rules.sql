-- Per-target protocol rules inside one policy (ADR 0013, amended 2026-09-29).
-- rules holds extra {target_selector, protocols} pairs; the policy's own
-- target_selector and protocols stay as rule zero, so existing rows and
-- clients keep working unchanged.
ALTER TABLE access_policies ADD COLUMN rules JSONB NOT NULL DEFAULT '[]';
