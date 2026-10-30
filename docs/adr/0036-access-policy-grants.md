# 0036. An access policy is an audience and a list of grants, each with its own conditions

Date: 2026-10-30

## Status

Accepted 2026-10-30, with the owner's answers to the questions at the end (all as
recommended); ships in 1.8.0. Amends [ADR 0013](0013-policy-subject-group-or-user.md) (one subject per policy,
rules, revocation by the admitting policy) and the eligibility rule of
[ADR 0018](0018-just-in-time-access-approvals.md). Leaves ADR 0015 (retention), 0017
(databases), 0024 (autoscaling sessions) and 0034 (applications) as they are.

## Context

The product owner walked the live console on 2026-10-30 and called the Add policy form "a
fiasco". Five complaints, each of which is a defect of the model, not of the form:

1. **One subject.** "Applies to: a group / one user." A policy for the platform team and the two
   contractors who help them is three policies kept in step by hand.
2. **Tags as text.** Targets "by tag" is a textarea of `env=prod` lines. The owner wants key and
   value boxes, as AWS draws them, and no `key=value` typing anywhere in the console. A shared
   `TagEditor` (rows of Key and Value, add and remove a row) is being built in
   `web/src/components/` for every tag field.
3. **One list of everything.** "By name" lists every target of every kind (a Google application,
   a Linux host, an internal Nginx, a Windows box) in one checklist, with a separate protocol
   checklist under it. Tick a Linux and a Windows host and nobody can say which protocol goes
   with which. "More rules" repeats the same pair. The owner wants: choose the kind first (host,
   database, application, autoscaling group), see only targets of that kind, pick them, and
   choose the protocol per target from the protocols that target actually serves.
4. **One set of conditions.** Allow clipboard, Allow file transfer, Require an authenticator and
   Require approval sit at the bottom and apply to everything in the policy. The owner needs them
   per set of targets: some servers just-in-time, others standing, in the same design.
5. **Weight.** The form explains itself in paragraphs. The console must say less; the docs say
   more.

What the code does today (`internal/policy/policy.go`): a policy has exactly one of `group_id`
and `user_id`; a base `target_selector` (ids, ASG ids, a tag map matched as AND of exact values)
with `protocols`, plus up to 32 `rules` of the same shape; and one set of windows, limits and
flags for the whole policy. A tag selector matches any target carrying the tags, whatever its
kind, so `env=prod` with `ssh` also "covers" the prod database, which the portal then lists for
SSH and connect refuses with `no_credential`. On overlap, the policy with the shortest idle
timeout sets every term of the session but retention, so a stricter overlapping policy can lose
its MFA or clipboard setting to a looser one with a shorter idle. Live sessions are registered
under the one policy that admitted them and are judged by that policy alone when it changes.

Benchmarks (what mature products do, and what is borrowed):

| Product | Model | Borrowed here |
|---|---|---|
| Teleport roles | Labels scoped by resource kind (`node_labels`, `windows_desktop_labels`, `db_labels`, `app_labels`); a label value may be a list (OR), keys AND; a user's roles merge to the least permissive option; allow and deny; access requests | Kind-scoped tag match, keys AND and values OR, least-permissive merge. Not deny. |
| HashiCorp Boundary | A role = principals (users, groups, managed groups) + grants; host sets static or dynamic; session limits belong to the target | Many principals per policy; limits travel with the target set, not the person. Not scopes. |
| StrongDM | Roles made of access rules, static or dynamic (type filter + tags); standing access from roles, just-in-time from access workflows | Type before tags; standing versus approval as a property of the rule. |
| AWS IAM Identity Center | Permission set (what, with its session duration) × assignment (who, where) | "Who" separated from "what"; duration lives on the "what". |
| Azure PIM | Eligible versus active; per-role settings: MFA on activation, approval, maximum activation | Approval, MFA and maximum as settings of the thing granted. |
| Cloudflare Access | Include (OR), Require (AND), Exclude; session duration per policy | Confirms AND-of-keys and per-rule duration. Nothing further. |

Alternatives considered are at the end.

## Decision

**A policy is an audience and a list of grants. The policy says who (many groups and/or users)
and whether it is on. Each grant says, completely and on its own, what: a kind of target, which
targets of that kind, which protocols on each, and under what conditions a session opens and
runs. When several grants admit the same session, each term is the strictest among them.**

### Model

Policy level, and nothing else:

| Field | Rule |
|---|---|
| `name`, `description` | as today (name 1-64, unique) |
| `enabled` | off: the policy grants nothing, its live sessions are re-checked (below) |
| `subjects` | 1-64 rows of `{kind: group \| user, id}`; no duplicates; a user subject must be able to connect (an auditor-only account is refused `422 review_only_subject`, as today; group members are not inspected, the connect routes refuse them) |
| `grants` | 1-32 grants |

Grant level. Every condition is here, so one grant is a complete sentence ("SSH to web-01 and
web-02 and every host tagged env=prod, standing, authenticator required, 15 minutes idle,
weekdays 09-18 Berlin") and the console can print it on one line. There is no inheritance from
the policy and no override: one place to look, and overlap only ever compares grants with grants.
The console offers "same conditions as the grant above" when a grant is added, so repetition
costs one click and nothing in the model.

| Field | Rule |
|---|---|
| `id` | server-made (`store.NewID`); the client sends it back on edit so requests and audit keep pointing at the same grant; an unknown id is refused |
| `kind` | `host`, `database`, `application`, `autoscaling` |
| `targets` | 0-200 rows of `{id, protocols}`; no id twice in one grant; each id must exist, be live (not retired or deleted) and be of the grant's kind (`422 kind_mismatch` names the id); `protocols` 1+ from the kind's set |
| `tags` | optional `{match: {key: [values]}, protocols}`; 1-32 keys, 1-16 values per key, each 1-64 characters, no empty value; a target matches when **every key is present with one of its values**; `protocols` 1+ from the kind's set. Scoped by the grant's kind: a host grant's tags match hosts only |
| at least one of `targets`, `tags` | a grant that names nothing is refused, as a policy that grants nothing is today |
| `access` | `standing` or `approval` (replaces `require_approval`) |
| `require_mfa` | default on |
| `allow_clipboard`, `allow_file_transfer` | default off |
| `idle_timeout_minutes` | 1-1440, default 15 |
| `max_session_minutes` | null or 1-10080 |
| `time_windows` | as today; empty means always |
| `retention_days` | null or 1-3650; a target's own value still wins (ADR 0015 amendment) |
| `sign_in` | `target` (default): the target's slot decides, exactly as before this ADR (its vaulted credential, its SSH authority, or *User supplied*); `own`: the person's own login whatever the slot holds, typed at connect time (a password, or over SSH their own key) and never stored. See *Signing in* below |

**Signing in** (added 2026-10-30, from the walkthrough). How a person signs in to the target is
said by the grant, not only by the target: an administrator's vaulted credential is for
privileged, often just-in-time access, while the same people may reach other machines as
themselves. Today *User supplied* is a choice on the target's credential slot, so one target
signs in one way for everyone. With `sign_in` on the grant, the platform team's approval grant
can use the vaulted `root` credential on the database hosts while a contractors' grant on the
same hosts asks for their own login.

`target` means the slot decides, as it does today, *User supplied* included; `own` means the
person's own login whatever the slot holds, so an `own` grant needs nothing bound. `sign_in` is
not a limit, so the strictest-of-each rule does not apply to it. The connect rule, in one
sentence: **if a deciding grant says `target`, the slot decides; if they all say `own`, the
person's own login is asked for.** Where both are allowed, the access portal offers *Use my own
login* beside the protocol, and the session's audit event records which was used.

Migration: every grant gets `target` and no slot is touched, so who signs in how is exactly as
before. (A first draft moved *User supplied* slots into `own` grants and emptied the slots;
one tag grant can cover a host whose slot is *User supplied* and one whose slot is vaulted, so
that could not be expressed, and an emptied slot would have broken the `target` grants still
covering it.)

Protocols per kind are fixed by the server and the only ones the console offers:

| Kind | Protocols | Note |
|---|---|---|
| host | ssh, rdp, vnc, winrm | the console narrows each target's chips to its probed capabilities, or, before a probe, to its OS family (linux: ssh, vnc; windows: rdp, winrm, ssh; other: all four); the server checks the kind, not the OS, because a Windows host with OpenSSH is legitimate |
| autoscaling | ssh, rdp, vnc, winrm | chips are the group's declared capabilities |
| database | database | the console fills it in and shows nothing; the API still requires it, and refuses anything else |
| application | http | likewise |

Why each condition is per grant and not per policy:

- **Approval and MFA** are what the owner asked for per target set, and they are what Azure PIM
  and Teleport's access requests put on the thing granted, not on the person.
- **Clipboard and file transfer** are exfiltration controls of the target, not of the person.
- **Idle and maximum** are the session's terms; Boundary and Identity Center keep them with the
  target or the permission set. A JIT cap (`max_session_minutes` of an approval grant) must sit
  beside the approval switch it bounds.
- **Time windows** are the one condition that could be read as the audience's shift rather than
  the target's hours. They go per grant anyway: a split would be the only policy-level condition,
  and "prod only in office hours, staging always, same team" is a real policy. Each grant card
  shows them collapsed; "same conditions as above" copies them.
- **Retention** is an evidence rule about the target's recordings (prod longer), so per grant.

The kind of a connection target is derived, never stored on the policy: an autoscaling instance or
group is `autoscaling`; a target with an engine is `database`; one with an upstream is
`application`; else `host`. `policy.TargetRef` gains `Kind`, set by the three callers that build
it (connect, access requests, the portal listing). The constants and the kind→protocols table
live in `internal/protocol`, the leaf both `policy` and `target` import; `target.Target.Kind()`
and the ASG repository return them. `policy` must not import `target` (target imports policy for
the deletion guard), so the write-time inventory check goes through a small `policy.Inventory`
interface wired in `cmd/zanskar/main.go`.

Dynamic membership is unchanged in spirit: a named autoscaling group covers every healthy
instance it has now and later; a tag rule covers every target of its kind that carries the tags
when a connect is evaluated, so a host tagged tomorrow joins tomorrow and one untagged leaves at
its next connect (a live session is not re-checked for that; see revocation). Nothing is cached.

### Overlap

For one user, one target and one protocol, several grants across several policies may admit.
The rule, in one line for the console lead and the docs:

> **Standing access wins over approval; of the grants that let you in, each limit is the
> strictest.**

Precisely, `Evaluate` collects the enabled grants that cover the target's kind, the target and
the protocol and have a window open now (or none). If any is `standing`, the standing ones decide
and no approval is needed (ADR 0018 kept: an approval grant never lends its terms to a standing
session). Otherwise the approval grants decide and `RequireApproval` is true. Within the deciding
set:

| Term | Resolution | Why |
|---|---|---|
| idle timeout | shortest | as today |
| maximum session | shortest; null (none) loses to any limit | a limit someone set is a limit |
| clipboard, file transfer | allowed only if every grant allows | an exfiltration control one grant set is not undone by another |
| require MFA | required if any grant requires | a step one grant demands is not skipped |
| time windows | a filter, not merged: a shut grant does not admit | |
| retention | longest, as today | an evidence obligation |
| `Decision.Policy` (the session row's `policy_id`, the ticket's) | the grant with the shortest idle, ties by policy name then grant position | display and audit only; revocation no longer keys on it |

`Decision` also lists every deciding grant (`Grants: [{policy_id, policy_name, grant_id}]`) so a
refusal, the portal and the audit event can say which grants were in play.

Today's rule ("the shortest idle timeout wins and its flags apply") is dropped. ADR 0013 said a
later change "may take the most restrictive value of each flag instead"; this is that change. It
never widens: adding a grant can add access, but never loosens a term of access that already
exists. The price is that one person cannot be given the clipboard on a target their group may
not use it on; they must leave the stricter audience. That is the same additive-only posture
ADR 0013 chose, and the docs say so in one sentence.

### Evaluation and side effects

- **Connect** (`access.Gate.Admit`, both when the ticket is issued and when it is redeemed): as
  above, then the approval check (`HasActiveGrant` by user, target or group, protocol, unchanged)
  and the MFA check. The ticket carries the merged terms; the session row's `policy_id` is
  `Decision.Policy`.
- **Portal listing** (`GET /me/targets`, `/me/autoscaling-groups/{id}/instances`): each reachable
  thing is evaluated for the protocols of its kind only (a database for `database`, an
  application for `http`, a host for the four, a group for its capabilities), with
  `requires_approval` per protocol as today. A tag policy no longer makes a database appear under
  SSH; see Consequences.
- **Just-in-time requests** (ADR 0018): a request names a target or group and a protocol, as
  today. It is eligible when at least one enabled `approval` grant of the caller's covers it; the
  duration cap is the **shortest** `max_session_minutes` among those grants (a grant with none
  counts as `DefaultMaxGrantMinutes`), and the request records `policy_id` and the new `grant_id`
  of the grant that set the cap (ties as above), for the audit trail. Approval re-evaluates with
  the policies as they stand then (finding SEC-2, unchanged), so the recorded grant is a record,
  not an authority. Whether a request may be filed while the grant's window is shut is unchanged
  (it may; connect enforces the window). Standing access is never requested.
- **Live sessions.** One rule replaces the per-trigger rules of ADR 0013:

  > A live session is re-checked whenever the access that admitted it may have changed, and it
  > ends when a fresh connect would be refused now, or when its clipboard or file transfer would
  > now be off.

  The re-check runs the connect gate against the user's **current** access (every policy that
  applies to them), not against the one policy that admitted the session. That is what
  `GrantRevoked` already does; it ends the "another policy would let them straight back in, so
  they reconnect" detour of ADR 0013. A refusal is a refusal for any reason the gate knows:
  no grant covers the session, the policy is off, the subject is gone, the window is shut, an
  approval grant is required and no grant is active, an authenticator is required and none is
  enrolled. A session whose idle or maximum would now be shorter is **kept** on its old terms
  until it ends on its own (the maximum bounds it); numbers and windows do not pull a running
  session, exfiltration switches do. The gateway registry keeps, for each live session, the two
  switches it runs with (`gateway.Live.AllowClipboard`, `AllowFileTransfer`), beside the
  `PolicyID` it already keeps for display.

  Triggers, and whose sessions are re-checked:

  | Change | Sessions re-checked |
  |---|---|
  | policy edited (any field, a subject removed, disabled) | users covered by the policy before or after the edit |
  | policy deleted | users it covered, computed before the delete |
  | member removed from a group | that member |
  | group deleted | its members, after the delete (the policy survives; its group subject row goes) |
  | user deleted or disabled | all their sessions, as `admin_terminated` (unchanged) |
  | JIT grant revoked or expired | the user's sessions on that target and protocol (unchanged; same gate) |
  | target disabled, moved, trust lost | unchanged (ADR 0013, 2026-10-26) |

  A session ended this way closes as `policy_revoked`; a grant's expiry still closes as
  `max_duration`. A session that cannot be checked (its target no longer resolves) is kept and
  logged, as today. Each audit event still carries `live_sessions_ended`.

### API

`/api/v1/access-policies` keeps its path and verbs and changes shape. There is one shape; the
server does not translate.

```json
{
  "id": "p_7f3…",
  "name": "platform-prod",
  "description": "",
  "enabled": true,
  "subjects": [
    {"kind": "group", "id": "g_ops"},
    {"kind": "group", "id": "g_sre"},
    {"kind": "user",  "id": "u_contractor_1"}
  ],
  "grants": [
    {
      "id": "gr_01",
      "kind": "host",
      "targets": [
        {"id": "t_web01", "protocols": ["ssh"]},
        {"id": "t_dc01",  "protocols": ["rdp", "winrm"]}
      ],
      "tags": {"match": {"env": ["prod"], "tier": ["web", "api"]}, "protocols": ["ssh"]},
      "access": "approval",
      "require_mfa": true,
      "allow_clipboard": false,
      "allow_file_transfer": false,
      "idle_timeout_minutes": 15,
      "max_session_minutes": 120,
      "time_windows": [{"days": ["mon","tue","wed","thu","fri"], "from": "08:00", "to": "20:00", "tz": "Europe/Berlin"}],
      "retention_days": 365
    },
    {
      "id": "gr_02",
      "kind": "database",
      "targets": [{"id": "t_orders_db", "protocols": ["database"]}],
      "access": "standing",
      "require_mfa": true,
      "allow_clipboard": false,
      "allow_file_transfer": false,
      "idle_timeout_minutes": 30,
      "max_session_minutes": null,
      "time_windows": [],
      "retention_days": null
    }
  ],
  "created_by": "u_admin",
  "created_at": "…",
  "updated_at": "…"
}
```

- `POST` and `PUT` take the same body without `id`, `created_*`, `updated_at`; `PUT` replaces the
  whole policy, and left-out switches take their defaults, as documented today. Grants without an
  `id` are new; grants whose id is not on the stored policy are refused.
- **Legacy fields are refused, loudly.** A body carrying `group_id`, `user_id`,
  `target_selector`, `protocols`, `rules`, or any policy-level condition
  (`require_approval`, `require_mfa`, `allow_clipboard`, `allow_file_transfer`,
  `idle_timeout_minutes`, `max_session_minutes`, `time_windows`, `retention_days`) gets
  `400 legacy_policy_shape` with a message naming the field and this ADR. `GET` returns the new
  shape only; there is no read projection of `group_id` or `target_selector`, because a client
  that read the projection and wrote it back would silently drop every other subject and grant.
  No client of the old shape is left working by accident; every one we have (the console, the
  console command line, `hack/smoke.sh`, `hack/e2e.sh`, `hack/screenshots/seed.sh`, the OpenAPI
  examples) changes in the same release, and the release notes call it a breaking change to the
  policy resource. The `group_id` and `enabled` query filters the OpenAPI document describes
  for the list were never implemented by the handler (it pages and nothing else); the new
  document drops them rather than promise a subject filter, and the console keeps filtering the
  small list on the client.
- New refusal codes: `kind_mismatch` (a named target is not of the grant's kind),
  `unknown_target` (a named target or group does not exist or is retired),
  `protocol_not_for_kind`, `legacy_policy_shape`. `review_only_subject` stays.
- `GET /me/access-requests` and `/access-requests` items gain `grant_id`.
- Audit: `policy.create`, `policy.update`, `policy.delete` details carry `subjects` (kinds and
  ids) and a `grants` summary (kind, protocols, number of targets, tag keys, access); never
  secrets. The group-delete event carries `policies_detached` (names) in place of the deleted
  policy list.

OpenAPI: `AccessPolicy`, `AccessPolicyWrite` replaced; `TargetSelector` and `PolicyRule` removed;
new `PolicySubject`, `PolicyGrant`, `GrantTarget`, `TagMatch`, `TargetKind`.

### Storage

```
access_policy_subjects
  policy_id  TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE
  group_id   TEXT REFERENCES groups(id) ON DELETE CASCADE
  user_id    TEXT REFERENCES users(id)  ON DELETE CASCADE
  CHECK ((group_id IS NULL) <> (user_id IS NULL))
  UNIQUE (policy_id, group_id), UNIQUE (policy_id, user_id)
  indexes on group_id, user_id

access_policies
  + grants  TEXT (SQLite) / JSONB (PostgreSQL), NOT NULL DEFAULT '[]' once the data step has run
  - group_id, user_id, target_selector, protocols, rules, time_windows, max_session_minutes,
    idle_timeout_minutes, allow_clipboard, allow_file_transfer, require_mfa, require_approval,
    retention_days

access_requests
  + grant_id TEXT   (no foreign key: a grant is a JSON member of its policy)
```

Grants stay JSON, as `rules` are today: a policy holds at most 32 of them, nothing queries across
grants in SQL (the deletion guard `Referencing` and the portal already scan in Go), and one shape
serves both engines. Subjects are a table because `ForUser` joins on them:

```sql
SELECT p.* FROM access_policies p
WHERE p.enabled = TRUE AND EXISTS (
  SELECT 1 FROM access_policy_subjects s
  WHERE s.policy_id = p.id
    AND (s.user_id = ? OR s.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)))
ORDER BY p.name
```

Reading a page of policies loads the subjects of the page in a second statement **after** the
first cursor is drained and closed (SQLite runs on one connection). `ForGroup` reads through the
subjects table. `group.Repo.Delete` no longer lists the policies bound to the group for the
audit event; the handler reads the names that will be detached before the delete and records
them as `policies_detached`. A policy whose last subject is deleted with its group or user
**survives with no subjects**: it grants nobody, the list marks it, and nothing was silently
destroyed or widened. Deleting it is the administrator's explicit act.

### Migration

Three versions, applied in order by `store.Migrate`, which gains Go steps interleaved with the
SQL files by version string (each step in its own transaction, recorded in `schema_migrations`
like a file; `Pending` lists them too). Nothing in the application reads the legacy columns after
the last step, and `zanskar migrate` leaves the database in the new shape in one run, so there is
no release in which two shapes coexist.

1. `0035_policy_grants.sql` (both engines, same name, portable): create `access_policy_subjects`;
   `ALTER TABLE access_policies ADD COLUMN grants` (nullable, no default; `NULL` means "not yet
   converted"); `ALTER TABLE access_requests ADD COLUMN grant_id TEXT`; copy subjects with
   plain SQL:
   `INSERT INTO access_policy_subjects (policy_id, group_id, user_id) SELECT id, group_id, user_id FROM access_policies`.
2. `0036_policy_grants_data`, a Go step the policy package registers with the migrator when it
   is loaded (`store.RegisterStep`, as `database/sql` drivers register), so no caller of
   `store.Migrate` can run the files without it: for every row with `grants IS NULL`, decode
   the legacy columns into a frozen copy of today's types (`internal/policy/legacy.go`, kept for
   the oracle test and this step only), build the grants, write them. The transform needs the
   inventory, because a legacy selector names ids without kinds: it reads `targets`
   (engine, app_upstream decide host, database or application) and `autoscaling_groups` in the
   same transaction. Rules, per legacy selector `S` with protocols `P` and the policy's one set
   of conditions `C`:
   - Named target ids become `targets` rows of the grant for that target's kind, each with
     `P ∩ protocols(kind)`; a target id no longer in the inventory, or one whose kind serves
     none of `P` (a host named by a `database`-only policy), is dropped from the policy and
     named in the step's log line (it granted nothing a connect could use).
   - ASG ids become one `autoscaling` grant with `P ∩ {ssh, rdp, vnc, winrm}` per group.
   - A tag map becomes one tag rule `{k: [v]}` on a grant **for every kind that `P` can reach**:
     `host` and `autoscaling` when `P` has any of the four port protocols, `database` when `P`
     has `database`, `application` when `P` has `http`. This is the exact equivalent of today's
     kind-blind match over the protocols a target of that kind can serve; the owner may delete
     the ones they never meant, and the list shows them plainly.
   - The base pair and each rule go through the same function; grants of the same kind with the
     same tag rule and the same protocols merge, and a target the base and a rule both name
     becomes one row with the union of their protocols; each grant carries `C` (`access` =
     `require_approval ? approval : standing`).
   - A policy that ends with no grant (every id gone) keeps the policy row with `grants = '[]'`
     and is logged; it granted nothing before. The list marks it `⚠ no grants` beside the
     `⚠ no subjects` mark; it can be deleted as it is, and its next edit must give it a grant.
3. `0037_policy_grants_drop_legacy.sql`: PostgreSQL drops the columns and the subject CHECK and
   sets `grants NOT NULL DEFAULT '[]'`; SQLite rebuilds `access_policies` under
   `-- migrate: foreign_keys=off` as 0006 and 0031 did, so the `policy_id` of past sessions and
   requests survives, and the framework's dangling-reference check runs after. 0037 is also the
   guard against a binary that runs the files without the step: `SET NOT NULL` on PostgreSQL
   and the rebuild into a `NOT NULL` column on SQLite both fail on any row the step has not
   converted, so legacy policies can never be dropped unconverted by mistake.

**What the migration promises**, and the tests that prove it (`internal/policy/migrate_test.go`,
over `storetest.ForEachBackend`, seeded with every legacy shape: group and user subjects; tags
only; ids only; ids and tags; ASGs; rules; each protocol combination; each flag; windows;
retention; a disabled policy; an id that no longer exists):

- For every user, every live target and group of the synthetic inventory (linux and windows
  hosts, a database, an application, an autoscaling group; tagged and untagged), every protocol
  **that thing can serve** (host and group: the four; database: `database`; application:
  `http`), and several instants (inside and outside the windows): `Allowed` and
  `RequireApproval` from the frozen legacy `Evaluate` over the legacy rows equal the new
  `Evaluate` over the converted rows. Access is additive under both rules, so this holds.
- Where exactly one legacy policy admits, the whole `Decision` is equal: idle, maximum,
  clipboard, file transfer, MFA, retention.
- Where several admit, the new terms are the strictest of each; the test asserts that and the
  ADR owns it as the intended change (Overlap, above). The new decision is never *looser* than
  today's: the test asserts each new term is at least as strict as the legacy one.
- For a protocol a target cannot serve (the prod database under `ssh`), the legacy evaluator may
  say allowed and the new one says denied; the test asserts only that the new one denies. The
  user saw `no_credential` before and sees nothing listed now (Consequences).
- The step is idempotent (a second run converts nothing), and a row inserted after the step by
  the new code is untouched.

A fuzz test (`policy_fuzz_test.go`) generates random legacy policies and inventories and checks
the first two bullets, as the existing fuzz checks `Evaluate` today.

### UI

Terse. Labels are one or two words; a hint is one line and appears only where the choice is not
self-evident. The paragraphs about clipboard semantics and rules move to the docs.

**List** (`/admin/policies`). One row per policy; one line per grant.

```
Access policies                                                        [ Add policy ]

 Name              Who                       Grants                                              On
 ───────────────── ───────────────────────── ─────────────────────────────────────────────────── ──
 platform-prod     ops, sre · +1 user        SSH · web-01, dc-01 (RDP, WinRM), env=prod · Approval · MFA · 15m    ●
                                             Database · orders-db · Standing · MFA · 30m
 staging           ops                       SSH · env=staging · Standing · MFA · 15m            ●
 grafana           everyone                  Application · grafana · Standing · 60m              ●
 legacy-dba        ⚠ no subjects             Database · env=prod · Approval · MFA · 15m          ○
                                                                              [Edit] [Delete]
```

Grant line = protocols · targets (names; a tag rule as `key=value`, chips in the editor) · access
· MFA if required · idle. Clipboard and file transfer appear only when on (`clipboard`, `files`).
"⚠ no subjects" is the one warning the list shows. The page lead is the overlap rule, one line:
*Standing wins over approval; of the grants that let you in, each limit is the strictest.*

**Editor** (`/admin/policies/new`, `/admin/policies/{id}`): a page, not a modal; three sections
in a column; a sticky footer. Nothing is a wizard: every section is visible and the first invalid
one is scrolled to on Save.

```
← Policies        New policy                                            [Cancel] [Create]

Policy
  Name          [platform-prod                     ]   Enabled [x]
  Description   [                                   ]

Who
  Groups        [ops ×] [sre ×] [ Search groups…        ▾]
  Users         [contractor-1 ×] [ Search users…       ▾]
                 review-only accounts are not offered

Grants
  ┌─ Grant 1 ───────────────────────────────────────────────────── [Duplicate] [Remove] [▴] ┐
  │ Type      (●) Host  ( ) Database  ( ) Application  ( ) Autoscaling                       │
  │                                                                                           │
  │ Targets   [ Search hosts…                 ]                                               │
  │           [x] web-01        linux     [SSH ✓] [VNC  ]                                     │
  │           [x] dc-01         windows   [RDP ✓] [WinRM ✓] [SSH  ]                           │
  │           [ ] web-02        linux                                                         │
  │           [ ] bastion       linux     (not probed: chips by OS)                           │
  │                                                                                           │
  │ Tags      Key            Value                                                            │
  │           [env        ]  [prod       ]  [–]                                               │
  │           [tier       ]  [web        ]  [–]                                               │
  │           [tier       ]  [api        ]  [–]        [+ Add]                                │
  │           Protocols for matching hosts  [SSH ✓] [RDP  ] [VNC  ] [WinRM  ]                 │
  │           every key must match; a repeated key is any of its values                       │
  │                                                                                           │
  │ Conditions                                                                                │
  │   Access   (●) Standing  ( ) Approval          Authenticator [x]                          │
  │   Clipboard [ ]   File transfer [ ]                                                        │
  │   Idle [15 ] min   Max [120 ] min   Keep recordings [365 ] days                           │
  │   Windows  Mon Tue Wed Thu Fri  08:00–20:00  Europe/Berlin   [–]      [+ Add window]      │
  └───────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─ Grant 2  Database · orders-db · Standing · MFA · 30m ───────── [Duplicate] [Remove] [▾] ┐
  └───────────────────────────────────────────────────────────────────────────────────────────┘

  [+ Add grant]   [+ Add grant, same conditions]
```

- **Who**: two multi-select pickers (type to filter, Enter to add, chips to remove). The user
  picker lists only accounts that can connect. A policy must have at least one subject to be
  saved; the hint under Users is the only sentence in the section.
- **Type** is the first control of a card and resets the card's targets, tags protocols and chips
  when changed. Database and Application cards show no protocol chips at all. Autoscaling cards
  list groups with their capabilities as chips.
- **Targets**: a searchable checklist of live targets of the kind. A checked row grows protocol
  chips: a host's probed capabilities, or its OS family's set when unprobed (with the one hint
  shown above); an autoscaling group's capabilities. A target with exactly one possible protocol
  has it ticked on check; otherwise nothing is pre-ticked. Save refuses a checked row with no chip
  (the row is marked, the footer says "Grant 1: web-02 has no protocol").
- **Tags**: the shared `TagEditor` (Key box, Value box, remove, add). A repeated key is OR of its
  values and is shown as such when the card is collapsed (`tier=web|api`). Below it, for host and
  autoscaling kinds, one protocol chip row for everything the tags match. One hint line.
- **Conditions**: one block, two lines of switches and numbers, windows last. Approval shows a
  one-line hint only when first selected: *the user requests, an admin approves (JIT)*.
- **Collapsed card header** = the grant's one-line summary, the same text as the list.
- **Duplicate** copies the whole card; **Add grant, same conditions** adds an empty card with the
  previous card's conditions. **Remove** asks nothing when the card is empty, confirms otherwise.
- **Footer** errors are the server's, verbatim, prefixed with the grant number; the console
  pre-checks the same rules (empty grant, kind and protocol, subject missing) so the common ones
  never make the round trip.
- **Delete** (list) confirms with: *Its subjects lose this access; live sessions it admitted are
  re-checked and end if nothing else admits them.*

Copy budget: no paragraph anywhere in the policy pages. Hints: three (review-only accounts,
unprobed chips, tag matching), plus the approval line on first selection.

## Consequences

- One policy for an audience of many groups and users; one grant per target set with its own
  approval, MFA, clipboard, file transfer, limits, windows and retention. "Some servers
  just-in-time, others standing, same design" is one policy with two grants.
- Grants are kind-scoped, so the portal stops listing protocols a target cannot serve: a tag
  policy that said `ssh` no longer shows the prod database under SSH (connect refused it with
  `no_credential` before). Real access is unchanged; the listing is narrower and honest.
  `reach()` in `internal/connect` evaluates each thing for its kind's protocols only.
- Overlap resolves each term to the strictest. A looser overlapping grant no longer lends its
  flags; a stricter one is no longer ignored because its idle was longer. One person cannot be
  loosened inside a stricter audience; they are moved out of it.
- Revocation re-checks against the user's whole access and ends sessions on refusal or an
  exfiltration switch turning off; it no longer ends a session another policy still covers, and
  it no longer ends a session because a number changed. The other side of strictest-of-each:
  **adding** a subject or a grant can tighten a running session. Put a user into a policy whose
  grant has the clipboard off on a target they are using with the clipboard on under another
  policy, and their effective clipboard flips off, so that session ends. Adding never loosens;
  it can tighten, live. `gateway.Revoker` replaces its four
  policy and group methods with one `Recheck(ctx, userIDs, cause)`; the user, target and
  JIT-grant methods stay. The group handler reads the member ids before the delete and calls
  `Recheck` **after** it, so the gate sees the subject row gone.
- **Deleting a group or a user no longer deletes policies.** The subject rows go; a policy may be
  left with no subjects, flagged in the list. The group-delete audit event names
  `policies_detached`. Deployments that used group deletion as a way to remove policies lose
  that shortcut and gain the policy back.
- **The policy API breaks**, deliberately and loudly (`400 legacy_policy_shape`). The console,
  the command line, the hack scripts and the OpenAPI document change in the same release; the
  release notes say so under "Breaking". No `/api/v2`: the product has no third-party API
  clients we know of, and a silent compatibility layer would have been the dangerous option.
- `store.Migrate` learns Go steps. This is the first; the facility is small (a version string
  and a function run in its own transaction) and the migration ordering trap (dropping columns
  before the data step reads them) is avoided by three versions.
- A frozen copy of today's model and evaluator lives in `internal/policy/legacy.go` for the data
  step and the oracle test. It is deleted together with the step in a later release, once every
  supported upgrade path has run it (one minor release later at the earliest; the release notes
  name the floor).
- `TagEditor` becomes the one way tags are entered; `parseTags` and `formatTags` in
  `web/src/pages/admin/lib.tsx` lose their last caller once `TargetForm` adopts it too.
- The ADR index gains a row; ADR 0013's status becomes "Accepted, amended by 0036"; ADR 0018's
  eligibility paragraph points here. Those edits are in the build plan, not in this file.

## Alternatives

- **Keep one policy = one subject (ADR 0013) and only fix the form.** The owner's first complaint
  is the model; three policies kept in step by hand is the thing being removed.
- **Policy-level conditions with per-grant overrides.** Two places to look and an inheritance
  rule to explain; the one-line grant summary would need "(inherited)" markers. Per-grant with
  "same conditions as above" costs one click and nothing in the model.
- **One protocol per grant (Teleport's kind = protocol).** Clean, and it would have removed the
  per-target chips. Rejected because a host serves several protocols and the owner asked for
  "the protocol per target, from what it supports" under one set of conditions; with one
  protocol per grant, "SSH to the fleet and RDP to the jump hosts, same approval" is two grants
  again.
- **Keep "shortest idle wins and lends its flags".** It can drop an MFA or clipboard restriction
  to a looser policy that happens to have a shorter idle, and it is not explainable in a line.
- **Deny rules.** Teleport has them; they need a precedence rule, they make "why can X reach Y"
  a two-list question, and the product's audiences are small. Additive-only stays; to narrow one
  person, take them out of the audience.
- **A policy language (Cedar, OPA/Rego).** Expressive, but opaque to a form: no per-grant card,
  no one-line summary, no chips limited to what a target serves; existing policies would become
  text nobody wrote; and the owner asked for less in the console, not a language. An export of
  policies to such a language for review is a possible later feature, not the model.
- **A tag wildcard (`*` = any value, "key present").** Useful and cheap to evaluate, but today
  any 1-64 character string is a legal tag value, so `env=*` is ambiguous until target validation
  reserves it too. Left out; a later ADR may reserve it in both places.
- **A read projection of the legacy fields for old clients.** A client that reads
  `group_id`/`target_selector` and writes them back drops every other subject and grant; that is
  the silent narrowing this ADR must not allow. Refuse loudly instead.
- **Grants and their targets as rows in their own tables.** Normal form, but nothing queries
  across grants in SQL, the policy is read and written whole, and two shapes (JSON for tags,
  rows for ids) would be worse than one.
- **Keep policies cascading with group deletion.** Deleting a group would destroy a policy that
  also names other groups and users. Detaching is the only choice that neither destroys nor
  widens.
- **A startup data transform with legacy columns kept for a release.** Less machinery than Go
  migration steps, but it leaves a release in which two shapes coexist and a window in which an
  older binary writes the old one. Three ordered versions in one run is simpler to reason about.

## Decisions of the product owner

Six choices this design made on the owner's behalf; on 2026-10-30 the owner took the
recommendation on each, and the release as 1.8.0.

| # | Question | Recommended | Other option |
|---|---|---|---|
| 1 | Time windows per grant or per policy? | Per grant ("prod in office hours, staging always, same team") | Per policy, the audience's shift |
| 2 | A policy whose last group or user is deleted | Kept, granting nobody, marked "no subjects" | Deleted with its last subject |
| 3 | An edit that only tightens a number (idle, maximum, window) | Live sessions keep their terms; clipboard or file transfer turned off ends them | End every affected session |
| 4 | A tag wildcard (`env` = any value) | Left out until tag values reserve `*` | Add it now |
| 5 | The API break | Same path, old shape refused with `400 legacy_policy_shape` | A new `/api/v2/access-policies` beside the old |
| 6 | How a person signs in, per grant (`sign_in`: the target's credential or their own login) | Per grant, as above, with *User supplied* on a slot migrated into the grants | Keep it on the target's slot only |

The API break and the data migration make this a minor release: 1.8.0.

## Defects of the current model found while writing this

Each is removed by the design above; none is fixed on its own before it.

- On overlap, the policy with the shortest idle timeout lends all its flags: a stricter
  overlapping policy's MFA or clipboard-off is lost to a looser one with a shorter idle.
- Just-in-time eligibility takes the first approval policy by name, so the duration cap depends
  on policy names, and it ignores time windows (a request can be approved for a shut window;
  connect still enforces the window).
- A tag policy granting `ssh` lists a database carrying the tag under SSH in the access portal;
  connect then refuses it with `no_credential`.
- The OpenAPI document describes `group_id` and `enabled` filters on the policy list that the
  handler never implemented.
- Evaluation order is by policy name, so renaming a policy can change a tie-break.

## Build plan

One pull request (the API break makes the console and the backend one change), fix commits kept
separate inside it; the console work can start on the API shape above while the backend lands in
the same branch.

**Backend**

1. `internal/protocol/protocol.go`: `KindHost`, `KindDatabase`, `KindApplication`,
   `KindAutoscaling`; `KindProtocols(kind) []string`; `ValidKind`.
   `internal/target/target.go`: `(*Target).Kind()`. `internal/asg`: groups report
   `KindAutoscaling`.
2. `internal/policy/policy.go`: `Subject`, `Grant`, `GrantTarget`, `TagMatch`; `Policy` loses
   `GroupID`, `UserID`, `Selector`, `Protocols`, `Rules` and every condition; `Validate`
   (subjects, grants, kind→protocols, tag rules, limits); `(*Grant).Covers(TargetRef, proto)`;
   `(*Policy).References(targetID, asgID)` over grants; `TargetRef.Kind`; `Evaluate` with the
   strictest-of-each merge and `Decision.Grants`; `Inventory` interface. Tests in
   `policy_test.go` (validation table per kind; covers; a merge table for every term, including
   null maximum versus a limit, MFA OR, clipboard AND, retention max; windows as a filter;
   standing over approval; `Decision.Policy` tie-break) and `policy_fuzz_test.go`.
3. `internal/policy/legacy.go`: frozen legacy types and `legacyEvaluate`; `Transform(legacy,
   inventory) []Grant`; an `init` that registers the step. `internal/store/migrate.go`: `Step`
   (`Version string`, `Run func(ctx, *sql.Tx, driver string) error`) and `RegisterStep`
   (`store` cannot import `policy`; a fresh database has no policy rows, so a test binary
   without the policy package migrates as well); steps sort with the files by version and are
   recorded in `schema_migrations`; `Pending` lists them;
   `MigrateUpTo(ctx, db, version, steps...)` for tests that must seed rows at an older schema,
   and `storetest.ForEachBackendUpTo`. Migrations `0035_policy_grants.sql`,
   `0037_policy_grants_drop_legacy.sql` in both `migrations/sqlite/` and `migrations/postgres/`
   (same names; the SQLite 0037 under `-- migrate: foreign_keys=off`). Tests:
   `store/migrate_test.go` (a step runs once, in order between its neighbours, is recorded,
   fails the run when it fails, and a fresh database migrates without it); `policy/migrate_test.go`
   on each backend: migrate up to 0034, seed the legacy shapes, migrate the rest with the step,
   then the oracle assertions of Migration above, idempotency and the dropped-id cases.
4. `internal/policy/repo.go`: `cols` without legacy columns; `Create`/`Update` write subjects
   in the policy's transaction (delete and re-insert on update); `Get`/`List` load subjects
   after draining the first cursor; `ForUser` via subjects; `ForGroup` via subjects;
   `UsersCovered(ctx, subjects) []userID` (direct users plus group members) for revocation;
   `Referencing` over grants. `backends_test.go`: subjects join on both engines, JSONB
   round-trip of grants, cascade of a group and a user subject leaving a zero-subject policy,
   `UsersCovered`.
5. `internal/policy/handlers.go`: new `input`; `legacy_policy_shape` refusal; inventory check
   (`kind_mismatch`, `unknown_target`, `protocol_not_for_kind`); `review_only_subject` for every
   user subject; `UsersCovered` before and after an update and before a delete, passed to the
   revoker; audit details. `handlers_test.go` for each refusal and the happy path;
   `handlers_revoke_test.go` adapted to `Recheck(userIDs)`.
6. `internal/gateway/revoker.go`: `Recheck(ctx, userIDs []string, cause error) int` replaces
   `PolicyDeleted`, `PolicyChanged`, `GroupMembersRemoved`, `GroupDeleted`; `registry.go`:
   `Live.AllowClipboard`, `Live.AllowFileTransfer` set by every bridge from the ticket.
   `internal/connect/revoke.go`: `recheck(sessions)` runs `gate().Admit` for the user's current
   access and ends on refusal or an exfiltration switch now off; `GrantRevoked`/`GrantExpired`
   use it with the target and protocol filter. `connect/revoke_test.go` and
   `revoke_withdrawn_test.go`: clipboard flipped off ends; idle shortened keeps; a subject
   removed ends; a second standing policy keeps a session whose admitting policy was deleted;
   group deleted ends members' sessions after the delete; approval switched on without a grant
   ends; MFA switched on without an authenticator ends.
7. `internal/group/group.go` `Delete` (no policy listing); `group/handlers.go`: read the names
   to detach and the member ids before the delete, call `Recheck` after, record
   `policies_detached`. `internal/user` handlers: unchanged (`UserRevoked`).
8. `internal/access/handlers.go`: `eligibleGrants` (enabled, `approval`, covers kind and
   protocol) and the shortest cap; `Request.GrantID`; `repo.go` reads and writes `grant_id`;
   `access_test.go`/`handlers_test.go`: two gated grants with different maxima cap at the
   shorter; `grant_id` recorded; approval re-evaluation still refuses `not_eligible`.
9. `internal/connect/connect.go` `myTargets` and `asguser.go`: kind-scoped protocol lists and
   `TargetRef.Kind`; `connect/mytargets_test.go`: a database under a host tag grant is not
   listed; an application lists `http` only; a group lists its capabilities.
10. `internal/cli/commands.go` `cmdPolicies`, `cmdPolicyShow` read `subjects` and `grants`;
    `cli_test.go` fixtures. `hack/smoke.sh`, `hack/e2e.sh`, `hack/screenshots/seed.sh` post the
    new shape. `docs/api/openapi.yaml` schemas and the `/access-policies` descriptions
    (`hack/check-site.py` and the openapi parse test still pass). `docs/adr/README.md` index
    row; ADR 0013 status line; ADR 0018 eligibility note; release notes under "Breaking".
    The user guide's Policies section (`site/guide/index.html`, "A policy binds one group or
    one user…", "the shortest idle timeout wins") is rewritten for subjects, grants, the
    overlap line and the clipboard and file-transfer semantics that leave the console
    (`hack/check-site.py` before touching `site/`). The group-delete confirmation in
    `web/src/pages/admin/UsersGroups.tsx` ("Its policies are deleted and the sessions they
    allowed end.") changes to say the group is removed from its policies and members' sessions
    are re-checked.

**Console**

11. `web/src/api/types.ts`: `PolicySubject`, `PolicyGrant`, `GrantTarget`, `TagMatch`,
    `TargetKind`, new `Policy`; `AccessRequest.grant_id`.
12. `web/src/pages/admin/lib.tsx`: `protocolsForKind`, `kindOf` moves here from
    `TargetForm.tsx`, `chipsFor(target)` (capabilities, else OS family), `grantSummary`.
13. `web/src/pages/admin/Policies.tsx` becomes the list (rows above, `⚠ no subjects`, delete
    confirm); new `PolicyEditor.tsx` (page, three sections, footer, scroll-to-first-error),
    `GrantCard.tsx` (type, targets with chips, `TagEditor` plus protocol row, conditions,
    collapsed summary, duplicate), `SubjectPicker.tsx` and `TargetPicker.tsx` (searchable
    multi-select with chips, keyboard: type, arrows, Enter, Backspace on a chip); routes in
    `pages.ts`. Depends on `components/TagEditor.tsx` (in progress); until it lands, the card
    renders the editor behind its prop interface with a stub in tests.
14. Tests: `Policies.test.tsx` (rows, grant lines, the warning, delete copy, failed load);
    `PolicyEditor.test.tsx` (refuses an empty grant, a checked target without a protocol, a
    missing subject, a database card sends `["database"]`, a repeated tag key aggregates to a
    value list, "same conditions" copies, legacy fields never sent, body shape equals the API
    above, PUT to the policy's address, the server's refusal shown with the grant number);
    `GrantCard.test.tsx` (type change resets chips, chips follow capabilities then OS,
    autoscaling chips follow the group); `SubjectPicker.test.tsx` (review-only hidden,
    keyboard); `web/e2e/admin.spec.ts`: create a two-grant policy through the editor and see its
    two lines in the list. Coverage floors per file as the standards baseline requires.

**Order of work**: 1 → 2 → 3 (model, evaluator and migration are testable without HTTP) → 4 → 5
→ 6 and 7 together (revocation touches both) → 8 → 9 → 10, with 11-14 in parallel from step 2
onward against the shape in this ADR. Before the merge: the full gate from `CLAUDE.md`,
`hack/smoke.sh` against a fresh database, and `hack/smoke.sh` against a database migrated from
the previous release with the seed policies of `hack/screenshots/seed.sh` loaded first.

## Amendment (2026-10-30): the list shows the loosest terms; deleting a target takes it out of its grants

Accepted by the product owner on 2026-10-30, after a walkthrough of the live 1.8.0 console. Two
parts of this record change.

**The list.** One line per grant (UI, above) does not scale. A policy of twelve grants filled
twelve lines and repeated its terms on each. The cells now summarise; the detail opens in place.

- **Grants** reads `3 grants · Host 2 · Autoscaling 1`, with a muted second line,
  `N targets · tag env test` (or `N tag rules`).
- **A new Access column** shows the **loosest** term across the grants. Each grant admits on its
  own, so one grant without MFA is enough to sign in without it, and the strictest-of rule only
  applies once several grants admit the same session.
  - `Standing` or `Approval`, or `Standing ×7 · Approval ×5` when they are mixed;
  - `MFA` only when every grant requires it;
  - a danger badge `standing, no MFA ×N` for grants that admit at once with no second factor;
  - a warning badge `no MFA ×N` for approval grants without MFA;
  - `clipboard`, `files` and `own login` only when some grant turns them on (`×N` unless all
    do).
  - Idle, maximum, windows and retention stay out of the list.
- **Expanding a policy** (a button with `aria-expanded`; Enter or Space) opens a full-width row
  under it holding a table of its grants. The columns are kind, targets or tags with their
  protocols (the first few, then `+N`), access, MFA (`no MFA` written out), clipboard and files,
  sign-in, idle and maximum, windows, and retention.
- **Who** shortens to `ops, sre +28 · 4 users` and opens the same way.
- **Edge cases:**
  - `no one` and `no grants` are badges;
  - a disabled policy is muted but keeps its badges' tone;
  - a target that is not found is counted only once every list has loaded, never printed as an
    id fragment.

**Deleting a target.** The deletion guard (`Referencing`, 409 `in_use`) is gone for hosts,
databases, applications and autoscaling groups. An administrator with many policies had to edit
each one before retiring a machine. Deleting now takes the target out of its grants, the way
deleting a group takes it out of its policies (decision 2):

- **A preview first.** `GET /targets/{id}/usage` (and the autoscaling equivalent) lists the
  policies that name the target, the grants it would empty, its live sessions, and its pending
  and approved access requests. The console shows that list and asks for the name.
- **One transaction.** The id leaves every grant's `targets`. A grant left with no target and no
  tag goes. **A policy left with no grant stays**, marked `no grants`, and grants nobody, as a
  policy left with no one does. Then the target is deleted. Tag grants are untouched.
- **Afterwards:**
  - its live sessions end with the reason `target_deleted`;
  - its pending and approved requests are cancelled;
  - `target.delete` carries `policies_updated` (names), and each policy changed gets its own
    `policy.update` with `removed_target`.
  - Nobody else's access changes: a removed id only ever narrowed a grant.

In the revocation table above, "target deleted" joins the rows: the sessions on that target end,
and nothing else is re-checked.
