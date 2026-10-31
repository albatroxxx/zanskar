-- The dashboard's trends (2026-10-31) count, per calendar day, sessions by
-- started_at and refused connections by action, outcome and ts. Neither had
-- an index that fits: the one holding started_at leads with user_id, and
-- the audit count went through the action index alone, reading every
-- session.connect event ever recorded once per day. Measured on SQLite's
-- single connection, the overview took 150 ms at 200,000 sessions and
-- 2.5 s at 500,000 audit events; with these, 1.5 ms and 85 ms. The
-- started_at index serves the 24-hour count and the Sessions page's time
-- range too.
CREATE INDEX access_sessions_started_idx ON access_sessions(started_at);
CREATE INDEX audit_events_action_outcome_ts_idx ON audit_events(action, outcome, ts);
