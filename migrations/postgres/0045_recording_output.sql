-- What a terminal session printed, for searching across recordings
-- (2026-11-03, idea 5; ADR 0041 amendment): one row per line of output, its
-- escape sequences stripped, seq its place among the indexed lines and at_ms
-- the time its first character was printed. Lines are cut at 2,000
-- characters and a recording keeps at most 5,000. The recording's file stays
-- the evidence; this is an index of it, deleted with it.
CREATE TABLE recording_output (
    recording_id  TEXT NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    at_ms         BIGINT NOT NULL,
    line          TEXT NOT NULL,
    PRIMARY KEY (recording_id, seq)
);
-- Whether the indexer has read the recording's output; recordings from before
-- this release are read once, in the background, while the setting allows.
ALTER TABLE recordings ADD COLUMN output_indexed BOOLEAN NOT NULL DEFAULT FALSE;
