-- Master-key rotation (ADR 0007, amended 2026-09-28) rewraps every data key
-- under the new master key; rotated_at records when a version's wrapping was
-- last replaced, so an operator can see the rotation took.
ALTER TABLE key_versions ADD COLUMN rotated_at TIMESTAMPTZ;
