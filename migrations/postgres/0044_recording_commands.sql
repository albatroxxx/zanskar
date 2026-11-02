-- The command lines a terminal session submitted, for searching across
-- recordings (ADR 0041): one row per command the recording's markers name,
-- seq being the marker's place among them (hidden input counts, so seq is the
-- player's marker index) and at_ms its time. The recording's file stays the
-- evidence; this is an index of it, deleted with it.
CREATE TABLE recording_commands (
    recording_id  TEXT NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    at_ms         BIGINT NOT NULL,
    command       TEXT NOT NULL,
    PRIMARY KEY (recording_id, seq)
);
-- Whether the indexer has read the recording; recordings from before this
-- release are read once, in the background.
ALTER TABLE recordings ADD COLUMN commands_indexed BOOLEAN NOT NULL DEFAULT FALSE;
