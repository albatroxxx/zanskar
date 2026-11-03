# 0042. Four eyes: a session waits until a second person watches it

Date: 2026-11-03

## Status

Accepted 2026-11-03, idea 7 of the 2026-11-03 live audit, which the owner asked to build.
Terminal sessions only, for now; see Consequences.

## Context

Some work should never be done alone: production databases' hosts, a payment system's
servers. An approval grant (ADR 0018) says someone agreed beforehand; it does not put anyone
beside the person while they work. Zanskar can already show a live session, read-only, to an
administrator or auditor (shadowing, ADR 0006), and every terminal session carries a tap a
watcher subscribes to before a byte flows.

## Decision

1. **A grant switch, `require_watcher`**, on host and autoscaling grants. Where several grants
   admit a person, one asking for it is enough (as for MFA).
2. **Held, not refused.** A terminal session (SSH, the WinRM console) it admits starts as usual:
   the target is dialled, the recording opened, the session registered so it can be watched. Then
   it waits: nothing passes between the person and the target, the person's terminal says
   *waiting for a second person to watch this session*, and the wait is audited
   (`session.watcher.wait`), which a notification channel can relay to the watchers (*A session
   waits for a second person to watch*, ADR 0039).
3. **Released by someone else.** The first watcher who is not the session's owner releases it; an
   administrator watching their own session counts for nothing. Watching needs the administrator
   or auditor role, as it always has, and is audited as it always was.
4. **Bounded.** Nobody within 5 minutes: the session ends `no_watcher`, saying why. A terminate or
   a revocation during the wait ends it with its own reason.
5. **What cannot be held is refused.** A desktop's guacd connection expects its client to answer
   each frame, and an application or database session starts containers of its own; none can wait
   like a terminal. A session of those kinds that a four-eyes grant admits is refused at Connect
   (`watcher_unavailable`), never run unwatched.

## Consequences

- A watcher who leaves does not end the session; four eyes is about the start being seen, and the
  recording keeps the rest. Ending a session when its last watcher leaves can come later.
- Desktops under four eyes need a hold that answers guacd while it waits (buffering what it draws);
  until then a four-eyes grant on a Windows host admits its WinRM console and refuses RDP.
- A person who closes the tab while waiting leaves the target's connection open until the wait
  ends, at most 5 minutes.

## Amendment, 2026-11-03: desktops and applications are held, and tags ask for four eyes

The live audit's idea 7 asked for four eyes on tagged targets (`env=prod`); 1.15.0 made it a grant
switch and held terminal sessions only. Two things change.

- **Held before guacd draws.** A desktop (RDP, VNC) or an application's browser cannot wait once
  guacd is drawing it, so it waits before: the session is live (in the registry, so it can be
  watched) but guacd is not dialled, nor the application's browser started, until someone other
  than its owner watches. The console says *waiting for a second person to watch this session*;
  a nop every few seconds keeps its tunnel open. A watcher of a held desktop is counted at once,
  which releases it, and their view joins guacd read-only as soon as the session has dialled it,
  so they see it from its first frame. Nobody within 5 minutes ends it `no_watcher`; it never
  dialled the target and keeps no recording. Watching a desktop now counts as watching for four
  eyes, as watching a terminal always did. Application grants may ask for four eyes.
- **Four eyes for tags.** *Four eyes for tags* (`access.four_eyes_tags`, Settings › Sessions):
  `key=value` pairs, comma-separated. Every session to a host or autoscaling group carrying one
  of them waits for a watcher, whichever policy admits the person, so a team's `env=prod` cannot
  be opened unwatched by a grant that forgot the switch. Changing it asks for a recent code, or a
  stolen session could empty it.
- **What cannot be watched is refused.** A database session has no screen to watch: under four
  eyes, by grant or by tag, it is refused at Connect (`watcher_unavailable`), never run
  unwatched. A database grant still cannot ask for four eyes.
