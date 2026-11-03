-- What an application's sessions were refused as dependencies (ADR 0037,
-- amended 2026-11-03, later), learned from the relay's log: the host and
-- port asked for, why it was refused, what asked for it (the browser's fetch
-- destination: script, image, iframe, document...) and the page's origin,
-- counted. The application's page in the console offers each private one
-- to allow. Rows go with the target.
CREATE TABLE app_dependency_refusals (
    target_id   TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    why         TEXT NOT NULL,
    what        TEXT NOT NULL,
    from_origin TEXT NOT NULL,
    count       INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (target_id, host, port, why, what, from_origin)
);
