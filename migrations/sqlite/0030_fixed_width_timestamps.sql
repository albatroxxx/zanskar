-- Timestamps compare as times on SQLite (M28; ADR 0003, amended 2026-10-11).
-- SQLite keeps timestamps as TEXT and compares them byte by byte. They were
-- written as RFC 3339 with trailing zeros trimmed, so inside one second text
-- order was not time order: "...T10:00:00.5Z" sorted before "...T10:00:00Z",
-- because '.' < 'Z'. The application now writes one form, UTC with exactly six
-- fractional digits, "2006-01-02T15:04:05.000000Z" (store.TimeArg). This
-- rewrites every stored timestamp to it: a shorter fraction, or none, is
-- padded with zeros; a longer one is truncated to the microsecond, which is
-- what PostgreSQL keeps.
--
-- Every value was written by the application in UTC with a "Z"; a value of
-- any other shape is left alone. NULL stays NULL, and a value already in the
-- form (27 characters) is not touched, so running this again changes nothing.
-- schema_migrations.applied_at is the migrator's own and stays as it is.
-- TestEveryTimestampColumnIsRewritten fails if a timestamp column is missing.

UPDATE access_policies SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE access_policies SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE access_requests SET decided_at = substr(decided_at, 1, 19) || '.' || substr(rtrim(substr(decided_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE decided_at LIKE '____-__-__T__:__:__%Z' AND length(decided_at) <> 27;
UPDATE access_requests SET expires_at = substr(expires_at, 1, 19) || '.' || substr(rtrim(substr(expires_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE expires_at LIKE '____-__-__T__:__:__%Z' AND length(expires_at) <> 27;
UPDATE access_requests SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE access_requests SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE access_sessions SET started_at = substr(started_at, 1, 19) || '.' || substr(rtrim(substr(started_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE started_at LIKE '____-__-__T__:__:__%Z' AND length(started_at) <> 27;
UPDATE access_sessions SET ended_at = substr(ended_at, 1, 19) || '.' || substr(rtrim(substr(ended_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE ended_at LIKE '____-__-__T__:__:__%Z' AND length(ended_at) <> 27;

UPDATE asg_instances SET launched_at = substr(launched_at, 1, 19) || '.' || substr(rtrim(substr(launched_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE launched_at LIKE '____-__-__T__:__:__%Z' AND length(launched_at) <> 27;
UPDATE asg_instances SET first_seen_at = substr(first_seen_at, 1, 19) || '.' || substr(rtrim(substr(first_seen_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE first_seen_at LIKE '____-__-__T__:__:__%Z' AND length(first_seen_at) <> 27;
UPDATE asg_instances SET last_seen_at = substr(last_seen_at, 1, 19) || '.' || substr(rtrim(substr(last_seen_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE last_seen_at LIKE '____-__-__T__:__:__%Z' AND length(last_seen_at) <> 27;
UPDATE asg_instances SET terminated_at = substr(terminated_at, 1, 19) || '.' || substr(rtrim(substr(terminated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE terminated_at LIKE '____-__-__T__:__:__%Z' AND length(terminated_at) <> 27;

-- The audit chain hashes an event's time as parsed, not as stored, so a
-- rewrite that keeps the instant keeps every hash. Since 1.0 events are stored
-- to the microsecond; a time with more digits is from a build before that,
-- its hash covers every digit, and truncating it would break the chain from
-- there to the head. Such a time (28 to 30 characters) is left as written.
UPDATE audit_events SET ts = substr(ts, 1, 19) || '.' || substr(rtrim(substr(ts, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE ts LIKE '____-__-__T__:__:__%Z' AND length(ts) < 27;

-- An anchor's signature covers its time as parsed, like an event's hash,
-- and anchors were always written to the microsecond, so padding keeps every
-- signature.
UPDATE audit_anchors SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) < 27;

UPDATE audit_export_state SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE auth_sessions SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE auth_sessions SET expires_at = substr(expires_at, 1, 19) || '.' || substr(rtrim(substr(expires_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE expires_at LIKE '____-__-__T__:__:__%Z' AND length(expires_at) <> 27;
UPDATE auth_sessions SET last_seen_at = substr(last_seen_at, 1, 19) || '.' || substr(rtrim(substr(last_seen_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE last_seen_at LIKE '____-__-__T__:__:__%Z' AND length(last_seen_at) <> 27;
UPDATE auth_sessions SET revoked_at = substr(revoked_at, 1, 19) || '.' || substr(rtrim(substr(revoked_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE revoked_at LIKE '____-__-__T__:__:__%Z' AND length(revoked_at) <> 27;
UPDATE auth_sessions SET mfa_verified_at = substr(mfa_verified_at, 1, 19) || '.' || substr(rtrim(substr(mfa_verified_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE mfa_verified_at LIKE '____-__-__T__:__:__%Z' AND length(mfa_verified_at) <> 27;

UPDATE autoscaling_groups SET last_synced_at = substr(last_synced_at, 1, 19) || '.' || substr(rtrim(substr(last_synced_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE last_synced_at LIKE '____-__-__T__:__:__%Z' AND length(last_synced_at) <> 27;
UPDATE autoscaling_groups SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE autoscaling_groups SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;
UPDATE autoscaling_groups SET deleted_at = substr(deleted_at, 1, 19) || '.' || substr(rtrim(substr(deleted_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE deleted_at LIKE '____-__-__T__:__:__%Z' AND length(deleted_at) <> 27;

UPDATE credentials SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE credentials SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;
UPDATE credentials SET rotated_at = substr(rotated_at, 1, 19) || '.' || substr(rtrim(substr(rotated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE rotated_at LIKE '____-__-__T__:__:__%Z' AND length(rotated_at) <> 27;
UPDATE credentials SET pending_created_at = substr(pending_created_at, 1, 19) || '.' || substr(rtrim(substr(pending_created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE pending_created_at LIKE '____-__-__T__:__:__%Z' AND length(pending_created_at) <> 27;
UPDATE credentials SET retired_at = substr(retired_at, 1, 19) || '.' || substr(rtrim(substr(retired_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE retired_at LIKE '____-__-__T__:__:__%Z' AND length(retired_at) <> 27;

UPDATE group_members SET added_at = substr(added_at, 1, 19) || '.' || substr(rtrim(substr(added_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE added_at LIKE '____-__-__T__:__:__%Z' AND length(added_at) <> 27;

UPDATE groups SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE groups SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE identity_providers SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE identity_providers SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE key_versions SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE key_versions SET retired_at = substr(retired_at, 1, 19) || '.' || substr(rtrim(substr(retired_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE retired_at LIKE '____-__-__T__:__:__%Z' AND length(retired_at) <> 27;
UPDATE key_versions SET rotated_at = substr(rotated_at, 1, 19) || '.' || substr(rtrim(substr(rotated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE rotated_at LIKE '____-__-__T__:__:__%Z' AND length(rotated_at) <> 27;

UPDATE mfa_recovery_codes SET used_at = substr(used_at, 1, 19) || '.' || substr(rtrim(substr(used_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE used_at LIKE '____-__-__T__:__:__%Z' AND length(used_at) <> 27;
UPDATE mfa_recovery_codes SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;

UPDATE mfa_totp SET confirmed_at = substr(confirmed_at, 1, 19) || '.' || substr(rtrim(substr(confirmed_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE confirmed_at LIKE '____-__-__T__:__:__%Z' AND length(confirmed_at) <> 27;
UPDATE mfa_totp SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;

UPDATE recording_storage SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE recording_views SET viewed_at = substr(viewed_at, 1, 19) || '.' || substr(rtrim(substr(viewed_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE viewed_at LIKE '____-__-__T__:__:__%Z' AND length(viewed_at) <> 27;

UPDATE recordings SET started_at = substr(started_at, 1, 19) || '.' || substr(rtrim(substr(started_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE started_at LIKE '____-__-__T__:__:__%Z' AND length(started_at) <> 27;
UPDATE recordings SET finished_at = substr(finished_at, 1, 19) || '.' || substr(rtrim(substr(finished_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE finished_at LIKE '____-__-__T__:__:__%Z' AND length(finished_at) <> 27;
UPDATE recordings SET retention_until = substr(retention_until, 1, 19) || '.' || substr(rtrim(substr(retention_until, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE retention_until LIKE '____-__-__T__:__:__%Z' AND length(retention_until) <> 27;
UPDATE recordings SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE recordings SET purged_at = substr(purged_at, 1, 19) || '.' || substr(rtrim(substr(purged_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE purged_at LIKE '____-__-__T__:__:__%Z' AND length(purged_at) <> 27;

UPDATE retention_policy SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE settings SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;

UPDATE targets SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE targets SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;
UPDATE targets SET last_probed_at = substr(last_probed_at, 1, 19) || '.' || substr(rtrim(substr(last_probed_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE last_probed_at LIKE '____-__-__T__:__:__%Z' AND length(last_probed_at) <> 27;
UPDATE targets SET deleted_at = substr(deleted_at, 1, 19) || '.' || substr(rtrim(substr(deleted_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE deleted_at LIKE '____-__-__T__:__:__%Z' AND length(deleted_at) <> 27;

UPDATE tls_certificates SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;

UPDATE users SET locked_until = substr(locked_until, 1, 19) || '.' || substr(rtrim(substr(locked_until, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE locked_until LIKE '____-__-__T__:__:__%Z' AND length(locked_until) <> 27;
UPDATE users SET created_at = substr(created_at, 1, 19) || '.' || substr(rtrim(substr(created_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE created_at LIKE '____-__-__T__:__:__%Z' AND length(created_at) <> 27;
UPDATE users SET updated_at = substr(updated_at, 1, 19) || '.' || substr(rtrim(substr(updated_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE updated_at LIKE '____-__-__T__:__:__%Z' AND length(updated_at) <> 27;
UPDATE users SET last_login_at = substr(last_login_at, 1, 19) || '.' || substr(rtrim(substr(last_login_at, 21), 'Z') || '000000', 1, 6) || 'Z'
    WHERE last_login_at LIKE '____-__-__T__:__:__%Z' AND length(last_login_at) <> 27;
