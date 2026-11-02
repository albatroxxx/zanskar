-- An application's further origins (ADR 0037, amended 2026-11-02): a JSON
-- array of {"name", "url"} the session's browser reaches beside the
-- upstream, which stays in app_upstream as the page the browser opens.
-- NULL for every target that has none, which is every target until an
-- administrator adds one.
ALTER TABLE targets ADD COLUMN app_endpoints TEXT;
