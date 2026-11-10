# 0047. A lifecycle is declared once, and the state a person sees is the state the gateway computed

Date: 2026-11-09

## Status

Proposed 2026-11-09, built the same day on the owner's instruction ("find all of the implicit
state machines in Zanskar; make the best decision that elevates the user, developer and agent
experience without breaking anything"). The open questions at the end are the owner's to decide;
nothing in this batch changes a stored value, removes a field or renames a word the owner chose.

## Context

A review of main at 1.18.8 (2026-11-09) found about thirty records whose lifecycle is a state
machine, and found it written implicitly: the states live in nullable timestamp columns, flags
and string literals; the moves between them are the `WHERE` clauses of separate `UPDATE`
statements; and the state a person sees is recomputed by whoever shows it. Of the thirty, three
have a named Go type (`access.Status`, `user.Status`, `target.HostKeyStatus`); none has a table of
allowed moves. The console recomputes a state from raw fields in 105 places; the command line, the
OpenAPI document and the Terraform provider each hold copies of their own. Where the copies
disagree, the product is wrong in a way no single test catches:

- An account locked out after five wrong passwords shows **Active** in the Users table: the
  lockout writes `locked_until`, the table reads `status`.
- The admin **Active grants** list shows a grant whose window has passed until the sweeper runs,
  with a Revoke button; the dashboard tile beside it does not count it.
- Sessions end with the reason `target_deleted`, which the console renders, but the Go constants
  and the OpenAPI enum do not know it; the health endpoint's documented words (`degraded`, `down`)
  are emitted nowhere, and its real words are documented nowhere.
- A second authority key rotation can be prepared while the previous retired key is still waiting
  to be removed from targets; the next cut-over overwrites the reminder.
- An enrolled user whose password an administrator reset types a correct code and stays on the
  code form: the sign-in page's step machine never reads the next step the gateway reports.
- "Live" is derived three ways (`ended_at`, `end_reason`, the registry), "retired" means six
  things, "pending" five, "active" five.

The full inventory, with every write site, guard and reader cited, is in the batch's working notes
(`bin/review-2026-11-09/`). This ADR records what was decided about it.

## Decision

1. **`status` is what was set; `state` is what holds now.** A record keeps its stored `status`
   (an administrator's choice: `active`, `disabled`; a request's decision: `approved`). It gains a
   computed `state`: what is true of the record at the moment it is read, from the row and the
   clock. An approved grant past its window has `status: approved` and `state: expired` before
   the sweeper writes it; a user with `locked_until` in the future has `status: active` and
   `state: locked_out`. Every `state` field's OpenAPI description carries this sentence.
2. **One declaration per lifecycle.** `internal/states` holds a small declaration type: the
   record's name, its states in order, the allowed moves (from, to, and the audit action or verb
   that makes the move), and a typed refusal `*states.Error` whose message names both states
   ("the request is denied; only a pending request becomes approved"). Each domain package
   declares its lifecycle beside its types (`session.Lifecycle`, `user.Lifecycle`, ...) and
   writes **one** derivation, `StateOf(row, now)`, pure over the struct. A declaration is data: it
   does not route writes. The SQL predicate in the statement stays the real guard; the
   declaration says what the predicate must be and names the refusal.
3. **The API carries `state`** on every lifecycle record, as an additive field. This batch:
   sessions (`live`, `ended`), recordings (`recording`, `finished`, `lost`, `purged`,
   `discarded`), targets (`active`, `disabled`; `retired` is declared and never returned, a
   retired row is invisible by construction), the certificate pins of a target (`tls_status`,
   `winrm_tls_status`: `none`, `pinned`, `changed`, the host key's words), users (`active`,
   `locked_out`, `disabled`, `locked`), access requests (the stored status, with a lapsed approval
   reading `expired`), API tokens (`active`, `expired`, `revoked`), autoscaling groups (`active`,
   `disabled`) and their instances (`healthy`, `unhealthy`, `terminated`), the SSH authority's
   rotation (`rotation_state`: `none`, `prepared`, `cut_over`) and a policy's access review
   (`review_state`: `never_reviewed`, `current`, `due`).
4. **The console reads `state` and derives nothing.** One label table, `web/src/api/states.ts`,
   maps each lifecycle's states to the words and tone the console shows; one `StateBadge` renders
   it. Pages that recomputed a state switch to the field. The words are the ones the owner already
   chose where they existed ("live", "Deleted", "Next key prepared", "Cut over", "review due");
   the new words are listed under Consequences so they get one look.
5. **Guard tests keep the copies honest**, in the style of `TestActionsMatchConsoleLabels`:
   every exposed lifecycle's states have a console label and no label is stale; every exposed
   lifecycle's states equal the OpenAPI enum of its `state` field; and `docs/lifecycles.md`,
   generated from the declarations with a state diagram per lifecycle, matches what the code
   declares. A lifecycle that is declared but not exposed (the connect flow's phases, the sign-in
   steps, the restart drain) is in the document and in no API field.
6. **A move from the wrong state is refused in the statement, with the states named.** The two
   that had none and bit: preparing a next authority key is refused while a retired key waits to
   be confirmed (`rotation_pending`, the existing code; the message says why), and revoking a
   grant whose window has passed is refused (`conflict`, the existing code; `state` already reads
   `expired`). The predicates are compare-and-swap on the columns the state is read from. No
   error code changes; messages improve.
7. **Documents follow the wire.** The OpenAPI enums that disagreed with the code are corrected to
   the code (`EndReason` gains `target_deleted`; `Health.status` says what the server sends;
   `Recording.purged_at`, `Drain.action` and `AsgInstance.host_key_source` are added; fields
   never emitted are removed). The code does not start emitting words nobody asked for.
8. **Findings outside the declaration are fixed in the same batch when the fix is small and
   wrong-state in nature**, each with a regression test: the stranded sign-in step; the command
   line's `tls` command reading the wrong depth; the SFTP registry outliving a session that
   revocation ended. The rest are listed as owed, below.

## Consequences

- Reading a list, the console, the command line, an API client and the Terraform provider see the
  same word for the same fact, computed once. A client that polls can act on `state` without
  re-implementing the clock.
- Adding a state or a move is one edit in one place; the guard tests then name every copy that
  must follow (the label table, the OpenAPI enum, the document). Forgetting one fails the build
  instead of shipping a mismatch.
- New words, each already spoken somewhere in the product and now given a name: `locked_out`
  (the console had no word for it), `lost` for a recording whose session ended before it was
  finished (the audit event and the notification said "lost"), `prepared` and `cut_over` for the
  rotation (the console said "Next key prepared" and "Cut over"), `changed` for a certificate a
  probe saw replaced (the host key already said `changed`), `never_reviewed`, `current` and
  `due` for a review (the console said "Never reviewed" and "review due").
- Behaviour that changes: a second rotation cannot be prepared over an unconfirmed retired key (the
  console hides the button meanwhile); revoking a lapsed grant answers 409 and the Approvals page
  reloads on it; the Users table shows a locked-out account as such; the sign-in page moves to the
  password change after a correct code when one is owed. Everything else is additive.
- `status` and `state` can differ by design. The OpenAPI document says so on every `state` field,
  and `docs/lifecycles.md` has the derivation of each.
- Not built, recorded as owed (each needs a decision or a design the owner has not asked for):
  - **The starting phase.** A session between its row and its registration cannot be terminated,
    revoked, counted by the caps or waited for by the drain; terminate closes the row and the
    bridge starts anyway. Fix: register before the dial, or make every control path consult the
    starting set. Design, not a patch.
  - **Row versus audit on a failed end.** `run.end` records `session.end` even when the row write
    failed; the sweep then closes the row as `error` with a second event. The one-line fix loses
    the real reason; the right one carries the detail to the sweep.
  - **Token state and the owner.** A token reads `active` while the gateway refuses it because its
    owner is disabled, demoted or owes a password change. Whether that is a token state or an
    owner state is the owner's call.
  - **`locked` versus `disabled`.** The stored `locked` status behaves exactly like `disabled` and
    only a raw PUT sets it. Merging them needs a migration.
  - **Enable and the lockout.** The OpenAPI document says setting `status: active` clears the
    lockout; the code never did, and making it do so needs the profile writer split from the
    status writer first (sync and SCIM write the status back today).
  - **SSO-only accounts** can be locked out for fifteen minutes by five wrong passwords typed by
    anyone, and the person then reads "could not be set up".

## Open questions for the owner

1. Should the Users table offer to clear a lockout (an Unlock action), now that it shows one?
2. Should `locked` be retired as a stored status (migration) or kept for a future meaning?
3. Should a token's `state` reflect its owner's state (`suspended`?), or is the 401 enough?
4. Should the starting phase be registered, so terminate and revoke reach it? That is the only
   high finding this batch does not touch.
