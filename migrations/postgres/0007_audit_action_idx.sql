-- The audit filter offers only the actions the log actually contains, so the
-- events page reads DISTINCT(action) each time it loads. Index the column so
-- that stays an index scan instead of a full table scan as the log grows.
CREATE INDEX audit_events_action_idx ON audit_events(action);
