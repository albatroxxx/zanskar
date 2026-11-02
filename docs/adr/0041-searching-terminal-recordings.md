# 0041. The command lines of terminal recordings are indexed and searched

Date: 2026-11-03

## Status

Accepted 2026-11-03, idea 5 of the 2026-11-03 live audit, which the owner asked to build.

## Context

"Who ran `systemctl stop nginx` on web-1 last week?" meant opening recordings one by one. Every
terminal recording already carries a marker per command line the person submitted, with its time
("(hidden input)" for what the remote did not echo, which is never stored), and the player seeks
to the i-th marker. Zanskar runs on SQLite and Postgres alike, so neither engine's full-text search
is open to it.

## Decision

1. **An index of the markers, beside the evidence.** `recording_commands` holds one row per command
   line: the recording, the marker's index (hidden input counted, so it is the player's index), its
   time and the line, cut at 2,000 characters. Hidden input is not stored. The recording's file stays
   the evidence; the index is derived from it.
2. **Filled in the background.** An indexer reads finished terminal recordings that are not yet
   indexed back from storage, 25 a pass every 30 seconds: new ones within a pass of finishing, those
   from before 1.15.0 once. A recording that cannot be read is marked indexed with nothing, so one
   lost file does not stall the rest.
3. **Searched portably.** `LOWER(command) LIKE ? ESCAPE '\'` with the term's own `%`, `_` and `\`
   taken literally, on both engines, newest sessions first, at most 500 hits.
4. **A search is a read of content.** Reviewers (administrators and auditors) only; at least two
   characters; each search is recorded as `recording.search` with its term and how many it found.
5. **Gone with the recording.** When retention deletes a recording, its rows go in the same step.
6. **A hit opens the recording at that command**: the Review link carries `?marker=<index>`, and the
   player seeks there once Play is pressed.

## Consequences

- Searching costs a table scan over command lines; a gateway's volume (thousands of sessions) reads
  it in milliseconds. A trigram index can come if a large deployment needs one.
- Desktop and application sessions have no command lines and are not searched.
- The index makes command lines queryable in the database; anyone with the database already had the
  recordings' paths, and on SQLite the files beside it.
