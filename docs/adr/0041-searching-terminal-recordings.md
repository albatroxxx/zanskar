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

## Amendment, 2026-11-03: what a session printed is searched too

The live audit's idea 5 asked for full-text search across terminal recordings; 1.15.0 searched
what was typed. Output is now searched as well.

- **A second index, `recording_output`.** One row per line a session printed: the stream's
  escape sequences (colour, cursor, window title) stripped, a carriage return that rewrites a
  line (a progress bar) leaving the line as it ended, backspaces applied. Lines with fewer than
  two visible characters, and a line the same as the one before, are left out. A line is cut at
  2,000 bytes; a recording keeps its first 5,000 lines (a log followed for an hour is searchable
  in its first ones, the recording keeping all of it).
- **One read for both.** The indexer reads a new recording once for its commands and its
  output; recordings from before this release are read once more, for their output, in the
  background.
- **Searched the same way.** `GET /recordings/search?in=output`: the same `LIKE ... ESCAPE` on
  both engines, reviewers only, each search recorded with its term and `in`. Each hit names the
  last command typed before the line (`after`), and Review opens the player at the moment the
  line was printed (`?at=<ms>`, turned into the player's idle-compressed clock).
- **A setting, on by default.** *Search what sessions printed* (`recordings.index_output`,
  Settings › Recordings). Off, the next pass empties the output index, and searching output
  answers `409 output_not_indexed`; on again, it is read again.
- **Gone with the recording.** Retention deletes a recording's output lines with its commands.

What a session printed holds what the person saw, a secret printed by `cat .env` included: the
index puts it in the database beside the command lines. The recording file already held it;
the setting is there for a deployment whose database is copied where its recordings are not.
Passwords typed at a prompt are not echoed, so they are not in the output either.
