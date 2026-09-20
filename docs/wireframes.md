# Zanskar wireframes

Low-fidelity screens for the user, admin and auditor portals. Each block is 80 columns wide.
The intent paragraph under each screen is the contract the React implementation must keep,
not the box art. Fields and enums match `docs/api/openapi.yaml` and migration 0001.

Conventions used in the drawings:

- `[ Button ]` is enabled, `( Button )` is disabled and greyed out.
- `(*)` and `( )` are radio buttons, `[x]` and `[ ]` are checkboxes.
- `____` is a text input, `▼` marks a select.

## 1. Login

### 1a. Password step

```
+------------------------------------------------------------------------------+
|                                                                              |
|                                  ZANSKAR                                     |
|                          Agentless access gateway                            |
|                                                                              |
|            +----------------------------------------------------+            |
|            |  Username                                          |            |
|            |  ______________________________________________    |            |
|            |                                                    |            |
|            |  Password                                          |            |
|            |  ______________________________________________    |            |
|            |                                                    |            |
|            |                                   [ Sign in ]      |            |
|            |                                                    |            |
|            |  ---------------------- or ----------------------  |            |
|            |  [ Continue with Okta ]   [ Continue with Entra ]  |            |
|            +----------------------------------------------------+            |
|                                                                              |
|                     v0.1.0  ·  Sign-in attempts are logged                   |
+------------------------------------------------------------------------------+
```

One form, no tabs. The provider buttons appear only for enabled identity providers and take
their label from the provider `name`. Failure shows one generic message, "Username or password
is incorrect", regardless of whether the account exists. A locked account gets the same message
plus a line saying to contact an administrator; the lock duration is not shown. The version
string comes from `/version` and nothing else about the build is displayed.

### 1b. TOTP step

```
+------------------------------------------------------------------------------+
|                                                                              |
|            +----------------------------------------------------+            |
|            |  Two-factor authentication                         |            |
|            |                                                    |            |
|            |  Enter the 6-digit code from your authenticator.   |            |
|            |                                                    |            |
|            |        [_] [_] [_] [_] [_] [_]                     |            |
|            |                                                    |            |
|            |                                   [ Verify ]       |            |
|            |                                                    |            |
|            |  Use a recovery code instead                       |            |
|            |  Signed in as jdoe  ·  Not you? Sign out           |            |
|            +----------------------------------------------------+            |
|                                                                              |
+------------------------------------------------------------------------------+
```

Shown when login returns `mfa_required`. The session exists but is not `mfa_verified`, so
every other route redirects here. The six boxes auto-advance and submit on the last digit.
"Use a recovery code instead" swaps the boxes for a single text field posting to the same
endpoint. When login returns `mfa_enrollment_required` the user lands on the enrollment
screen (QR code plus manual secret, then a confirm code, then recovery codes shown once with a
"I have saved these" checkbox gating the Continue button).

## 2. User portal

### 2a. Target list, Static tab

```
+------------------------------------------------------------------------------+
| ZANSKAR            My targets   My sessions                     jdoe ▼       |
+------------------------------------------------------------------------------+
|                                                                              |
|  [ Static ]  ( Autoscaling )          Search ______________________  Tags ▼  |
|                                                                              |
|  Name             OS       Tags               Terminal        Desktop        |
|  ---------------  -------  -----------------  -------------   -------------  |
|  bastion-01       linux    env=prod team=ops  [ SSH ]         ( none )       |
|  web-03           linux    env=prod           [ SSH ]         [ VNC ]        |
|  win-jump         windows  env=corp           [ WinRM ]       [ RDP ]        |
|  db-primary       linux    env=prod team=dba  [ SSH ]         ( none )       |
|  legacy-app       windows  env=staging        ( WinRM )       [ RDP ]        |
|  build-agent      linux    env=ci             ( SSH ! )       ( none )       |
|                                                                              |
|  ! Host key changed. An administrator must re-trust this target.             |
|                                                                              |
|                                                       < 1 2 3 >  50 per page |
+------------------------------------------------------------------------------+
```

The list is `GET /me/targets`. The Terminal column holds one button labelled with the
terminal protocol the policy allows (SSH or WinRM); the Desktop column holds the desktop
protocol (RDP or VNC). A button is enabled only when the protocol is in `allowed_protocols`.
When the target has the capability but the policy does not grant it, the button is greyed with
tooltip "Not permitted by your policy". When the target lacks the capability entirely the cell
reads "none". `blocked_reason` renders as a greyed button with an exclamation mark and a
footnote, as with `build-agent` above. Tags are chips; clicking one filters. Nothing on this
screen shows addresses, credential names or other users' activity.

### 2b. Target list, Autoscaling tab

```
+------------------------------------------------------------------------------+
| ZANSKAR            My targets   My sessions                     jdoe ▼       |
+------------------------------------------------------------------------------+
|                                                                              |
|  ( Static )  [ Autoscaling ]          Search ______________________  Tags ▼  |
|                                                                              |
|  Group              OS      Region       Healthy   Terminal      Desktop     |
|  -----------------  ------  -----------  --------  ------------  ----------- |
|  api-workers        linux   ap-south-1   4 / 5     [ SSH ]       ( none )    |
|  render-farm        linux   us-east-1    0 / 0     ( SSH )       ( none )    |
|  win-batch          windows eu-west-1    2 / 2     [ WinRM ]     [ RDP ]     |
|                                                                              |
|  Connecting to a group picks a healthy instance for you. You can choose a    |
|  specific instance from the connect dialog.                                  |
+------------------------------------------------------------------------------+
```

Same shape as the Static tab so the eye does not have to relearn it. The Healthy column shows
`healthy_count / total_count`. When `healthy_count` is zero every button is disabled with
tooltip "No healthy instances". The row is otherwise identical to a static target; the
difference surfaces in the connect dialog and, later, in the failover modal.

### 2c. Connect dialog

```
+------------------------------------------------------------------------------+
|                                                                              |
|      +----------------------------------------------------------------+      |
|      |  Connect to api-workers                                  [ x ] |      |
|      |                                                                |      |
|      |  Protocol         (*) SSH   ( ) RDP                            |      |
|      |                                                                |      |
|      |  Instance         ▼ Any healthy instance                       |      |
|      |                     i-0a1b2c3d  ap-south-1a  up 3h 12m         |      |
|      |                     i-0e4f5a6b  ap-south-1b  up 41m            |      |
|      |                     i-09c8d7e6  ap-south-1a  up 6m             |      |
|      |                                                                |      |
|      |  Credentials      This target asks for your own credentials.   |      |
|      |  Username         ______________________                       |      |
|      |  Password         ______________________                       |      |
|      |                   Not stored. Used for this session only.      |      |
|      |                                                                |      |
|      |  Session limits   Idle timeout 15 min · Max 4 h                |      |
|      |                   Clipboard off · File transfer off            |      |
|      |                                                                |      |
|      |                                  [ Cancel ]   [ Connect ]      |      |
|      +----------------------------------------------------------------+      |
|                                                                              |
+------------------------------------------------------------------------------+
```

The dialog opens from the row button with that protocol preselected. Protocol radios list
only `allowed_protocols`. The Instance select appears only for autoscaling groups and lists
the healthy pool from `GET /me/autoscaling-groups/{id}/instances`; "Any healthy instance"
lets the server choose. The credential block appears only when `credential_prompts` for the
chosen protocol has `mode=user_supplied`; for `ssh_key` it shows a private key textarea and
passphrase field instead of a password. The session limits line is read-only and echoes what
`ConnectTicket.policy` will return. Connect calls `POST /connect`, then opens the session view
with the ticket. The ticket is never shown to the user.

### 2d. Active terminal session

```
+------------------------------------------------------------------------------+
| api-workers/i-0a1b2c3d · SSH as deploy ⏱ 00:12:41  idle 14:07 [ Disconnect ] |
+------------------------------------------------------------------------------+
| deploy@ip-10-0-3-17:~$ uptime                                                |
|  14:02:11 up 3:12,  1 user,  load average: 0.31, 0.28, 0.25                  |
| deploy@ip-10-0-3-17:~$ sudo systemctl status api                             |
| ● api.service - API worker                                                   |
|      Active: active (running) since Sat 2026-09-20 10:50:02 UTC; 3h 12min ago|
| deploy@ip-10-0-3-17:~$ █                                                     |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
+------------------------------------------------------------------------------+
| Recording on · Clipboard off · Ctrl+Shift+D disconnect · Ctrl+Shift+? help   |
+------------------------------------------------------------------------------+
```

The terminal is xterm.js filling the viewport below a single top bar. The bar shows target
name and instance id, protocol and username, elapsed time, and a countdown to idle timeout
that resets on input and turns amber under two minutes. Disconnect asks for confirmation
only when a command is mid-flight (detected by output in the last two seconds). The bottom
strip states that recording is on so the user is never surprised later. Keyboard focus lands
in the terminal on open and stays there; every UI action has a keyboard chord. Resize events
send the `resize` control frame. Loss of the WebSocket shows an inline banner with Reconnect
(new ticket, same session id is not reused) rather than a modal, unless it is a `target_lost`
message, which opens the failover modal.

### 2e. Active desktop session

```
+------------------------------------------------------------------------------+
| win-jump · RDP as CORP\jdoe ⏱ 00:03:05 idle 14:58  [ Keys ▼ ] [ Disconnect ] |
+------------------------------------------------------------------------------+
|                                                                              |
|                                                                              |
|                         (remote desktop canvas,                              |
|                          scaled to fit, aspect kept)                         |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
|                                                                              |
+------------------------------------------------------------------------------+
| Recording on · Clipboard off · File transfer off · Resolution 1920x1080      |
+------------------------------------------------------------------------------+
```

Same bar as the terminal so the two feel like one product. The canvas is guacamole-common-js.
"Keys" opens a small menu for Ctrl+Alt+Del and other chords the browser would swallow. When
the policy allows clipboard, a paste icon appears in the bar and the bottom strip says
"Clipboard on"; when it does not, paste attempts show a brief toast saying the policy blocks
it, so users do not assume the session is broken. Resolution follows the browser viewport on
open and on resize, debounced.

### 2f. Failover modal

Appears only when the server sends `target_lost` for an autoscaling instance. Never for static
targets, and never on an ordinary network blip.

```
+------------------------------------------------------------------------------+
| api-workers/i-0a1b2c3d · SSH as deploy ⏱ 00:12:41             ( Disconnect ) |
+------------------------------------------------------------------------------+
|                                                                              |
|      +----------------------------------------------------------------+      |
|      |  Instance i-0a1b2c3d is no longer healthy                      |      |
|      |                                                                |      |
|      |  It left the healthy pool (Terminating). Your session has      |      |
|      |  ended and was recorded up to this point.                      |      |
|      |                                                                |      |
|      |  Switch to another healthy instance:                           |      |
|      |                                                                |      |
|      |   (*) i-0e4f5a6b    ap-south-1b    launched 41 min ago         |      |
|      |   ( ) i-09c8d7e6    ap-south-1a    launched 6 min ago          |      |
|      |   ( ) i-0f7e6d5c    ap-south-1c    launched 2 min ago          |      |
|      |                                                                |      |
|      |  Your shell state does not carry over.                         |      |
|      |                                                                |      |
|      |                                      [ Exit ]   [ Switch ]     |      |
|      +----------------------------------------------------------------+      |
|                                                                              |
+------------------------------------------------------------------------------+
```

When the pool is empty:

```
      +----------------------------------------------------------------+
      |  Instance i-0a1b2c3d is no longer healthy                      |
      |                                                                |
      |  It left the healthy pool (Terminating). Your session has      |
      |  ended and was recorded up to this point.                      |
      |                                                                |
      |  No healthy instances are available in api-workers right now.  |
      |                                                                |
      |                                                  [ Exit ]      |
      +----------------------------------------------------------------+
```

The modal is blocking; the dead terminal stays visible behind it so the user can read their
last output. The list is the `healthy_pool` array from the control frame, sorted by AZ then
launch time, first entry preselected. Switch calls `POST /sessions/{id}/failover` with the
chosen `asg_instance_id`, receives a new ticket, and opens the new session in the same tab
with a short banner "Switched from i-0a1b2c3d". If the user needed to supply credentials for
the first session, the same fields are asked again inside this modal before Switch enables;
Zanskar does not keep them. Exit returns to the target list. If a policy time window closed
during the outage, Switch is disabled with the reason.

### 2g. My sessions

```
+------------------------------------------------------------------------------+
| ZANSKAR            My targets   My sessions                     jdoe ▼       |
+------------------------------------------------------------------------------+
|                                                                              |
|  Started (UTC)       Target                   Protocol  Duration  Ended by   |
|  ------------------  -----------------------  --------  --------  ---------- |
|  2026-09-20 13:49    api-workers/i-0e4f5a6b   ssh       00:07:12  open       |
|  2026-09-20 13:36    api-workers/i-0a1b2c3d   ssh       00:12:41  target lost|
|  2026-09-19 17:02    win-jump                 rdp       01:48:30  you        |
|  2026-09-19 09:15    bastion-01               ssh       00:00:41  idle       |
|                                                                              |
+------------------------------------------------------------------------------+
```

Metadata only from `GET /me/sessions`. There is no play button and no hint that recordings
exist beyond the strip shown during the session. A failover pair is visually linked with a
small chain glyph on the row that has `failover_from_session_id`.

## 3. Admin portal

### 3a. Navigation

```
+------------------------------------------------------------------------------+
| ZANSKAR ADMIN                                                    admin ▼     |
+----------------+-------------------------------------------------------------+
| Targets        |                                                             |
| Autoscaling    |                                                             |
| Credentials    |                     (content area)                          |
| Policies       |                                                             |
| Users & Groups |                                                             |
| Identity Prov. |                                                             |
| Sessions       |                                                             |
| Audit          |                                                             |
| Recordings     |                                                             |
| Settings       |                                                             |
| ------------   |                                                             |
| Switch to      |                                                             |
|  user portal   |                                                             |
+----------------+-------------------------------------------------------------+
```

The admin portal is a separate route tree (`/admin/...`) that the bundle only mounts when
`/auth/me` returns the `admin` role, and that the server can bind to a separate listener. The
sidebar has exactly the ten items above. "Switch to user portal" is shown when the admin
also holds `user`. Audit and Recordings are the same read-only screens the auditor portal
shows (section 4); every view from either portal is itself audited.

### 3b. Target form with probe

```
+------------------------------------------------------------------------------+
| Targets  >  web-03                                              [ Delete ]   |
+------------------------------------------------------------------------------+
|                                                                              |
|  Name          web-03_________________     Status   (*) active ( ) disabled  |
|  Address       10.0.3.41______________     OS       ▼ linux                  |
|  Tags          [env=prod x] [team=web x] + add                               |
|  Notes         ________________________________________________________      |
|                                                                              |
|  Ports         SSH 22___   RDP 3389_   VNC 5900_   WinRM 5986_               |
|                                                                              |
|  Credentials   SSH    ▼ prod-deploy-key (ssh_key, vaulted)                   |
|                VNC    ▼ ask user (user_supplied)                             |
|                RDP    ▼ none                                                 |
|                WinRM  ▼ none                                                 |
|                                                                              |
|  +--------------------------------------------------------------------+      |
|  |  Probe result                        last probed 2026-09-20 12:04  |      |
|  |                                                                    |      |
|  |  ssh    reachable   18 ms                                          |      |
|  |  vnc    reachable   21 ms                                          |      |
|  |  rdp    closed                                                     |      |
|  |  winrm  closed                                                     |      |
|  |                                                                    |      |
|  |  SSH host key   SHA256:2Hm1kWm2v8lQ3o1n9p7Q9xL0Z2c5s8f1a4d7g0j3k6m |      |
|  |  Status         CHANGED   previously SHA256:9aB3...k2Qz            |      |
|  |                                                                    |      |
|  |  !  SSH connects are blocked until you trust the new key.          |      |
|  |     Confirm out of band that the host was rebuilt.                 |      |
|  |                                                                    |      |
|  |                              [ Probe again ]   [ Trust this key ]  |      |
|  +--------------------------------------------------------------------+      |
|                                                                              |
|                                                    [ Cancel ]   [ Save ]     |
+------------------------------------------------------------------------------+
```

Save is a `PATCH /targets/{id}`; changing Address warns that host key trust will reset. The
probe box is driven by `POST /targets/{id}/probe` and shows one line per protocol from
`ProbeResult.ports`. Capabilities are derived from the probe and not edited by hand here
except through a small "Declare manually" link for hosts that block probing. "Trust this key"
opens a confirmation that repeats the fingerprint and requires typing the last four
characters; the request echoes the fingerprint so a racing probe cannot approve the wrong
key. Status `pending` (first probe) shows the same button without the red warning. Delete
confirms with the target name and states how many open sessions will be terminated.

### 3c. Autoscaling group enrollment

```
+------------------------------------------------------------------------------+
| Autoscaling  >  Enroll group                                                 |
+------------------------------------------------------------------------------+
|                                                                              |
|  Name             api-workers___________        Provider   ▼ aws             |
|  Region           ▼ ap-south-1                  ASG name   api-workers-prod_ |
|  OS               ▼ linux                    Address  (*) private ( ) public |
|  Poll interval    30___ s                       Tags     [env=prod x] + add  |
|                                                                              |
|  Role ARN         arn:aws:iam::123456789012:role/zanskar-readonly_________   |
|                                                                              |
|  External ID      zk-7f3a9c2e-4b1d-4e8a-9c6f-2d5b8a1e0f7c        [ Copy ]   |
|                   Generated by Zanskar. Put it in the role's trust policy.   |
|                                                                              |
|  +--------------------------------------------------------------------+      |
|  |  Trust policy                                            [ Copy ]  |      |
|  |  {                                                                 |      |
|  |    "Version": "2012-10-17",                                        |      |
|  |    "Statement": [{                                                 |      |
|  |      "Effect": "Allow",                                            |      |
|  |      "Principal": {"AWS": "arn:aws:iam::210987654321:role/zk"},  |      |
|  |      "Action": "sts:AssumeRole",                                   |      |
|  |      "Condition": {"StringEquals": {"sts:ExternalId":              |      |
|  |                    "zk-7f3a9c2e-4b1d-4e8a-9c6f-2d5b8a1e0f7c"}}    |      |
|  |    }]                                                              |      |
|  |  }                                                                 |      |
|  +--------------------------------------------------------------------+      |
|  Permissions policy (least privilege)                            [ Show ]   |
|                                                                              |
|  Ports            SSH 22___   RDP 3389_   VNC 5900_   WinRM 5986_            |
|  Credentials      SSH    ▼ asg-deploy-key (ssh_key, vaulted)                 |
|                   RDP    ▼ none                                              |
|                                                                              |
|  [ Test assume role ]   not tested yet                                       |
|                                                                              |
|                                                    [ Cancel ]   [ Enroll ]   |
+------------------------------------------------------------------------------+
```

The External ID is generated client-side for display but the server generates the real one
on `POST /autoscaling-groups` and returns it with `trust_policy` and `permissions_policy`
already filled in; the form re-renders with the server values after Enroll. "Test assume
role" calls sync and reports the AWS error code on failure, never the request details. One
credential per protocol applies to every instance in the group. The group detail page after
enrollment shows the instance table from `GET /autoscaling-groups/{id}/instances` with
lifecycle state, LB health, probe health, the derived healthy flag, and a Sync now button.

### 3d. Sessions

```
+------------------------------------------------------------------------------+
| Sessions                    [x] Open only   User ▼   Target ▼   Protocol ▼   |
+------------------------------------------------------------------------------+
|  Started (UTC) User  Target                 Proto From IP     Dur.          |
|  ------------ ------ ---------------------- ----- ------------ -----        |
| 09-20 13:49 jdoe   api-workers/i-0e4f5a6b ssh 203.0.113.7 00:07 [Terminate ] |
| 09-20 13:12 asmith win-jump               rdp 198.51.100.2 00:44 [Terminate ]|
+------------------------------------------------------------------------------+
```

Terminate asks for an optional reason and confirms. Rows with a recording show a play button
that opens the same player as the auditor portal and records the view.

## 4. Auditor portal

### 4a. Audit events

```
+------------------------------------------------------------------------------+
| ZANSKAR AUDIT        Events   Recordings                      auditor ▼      |
+------------------------------------------------------------------------------+
|                                                                              |
|  Chain: [ VERIFIED 2026-09-20 13:50 UTC · 184,220 events ]   [ Verify now ]  |
|                                                                              |
|  Actor ▼   Action ______   Object ▼   Outcome ▼   From ________  To ________ |
|                                                                              |
|  #       Time (UTC)         Actor    Action                  Object    Result|
|  ------  -----------------  -------  ----------------------  --------  ------|
|  184220  09-20 13:49:02     jdoe     session.start           session   ok    |
|  184219  09-20 13:48:59     jdoe     connect.ticket          session   ok    |
|  184218  09-20 13:36:41     system   session.target_lost     session   ok    |
|  184217  09-20 13:30:10     admin    target.host_key.trust   target    ok    |
|  184216  09-20 13:29:55     admin    target.probe            target    ok    |
|  184215  09-20 13:21:07     -        user.login              user      FAIL  |
|                                                                              |
|  > 184217  details {"fingerprint":"SHA256:2Hm1..","previous":"SHA256:9aB3.."}|
|            prev_hash 4f9c…e21a   hash 7b03…9d5e                              |
+------------------------------------------------------------------------------+
```

The chain badge is green for `ok`, red with the `first_bad_id` and reason when verification
fails, and grey with "not verified in 24 h" when stale. Rows expand inline to show `details`
and both hashes. Failed logins show the attempted username only in details, not in the Actor
column, so a typo of a password into the username field is not broadcast in the list.

### 4b. Recordings

```
+------------------------------------------------------------------------------+
| ZANSKAR AUDIT        Events   Recordings                      auditor ▼      |
+------------------------------------------------------------------------------+
|  User ▼   Format ▼   From ________  To ________                              |
|                                                                              |
|  Started (UTC) User    Target                 Fmt        Size    Views       |
|  ------------  ------  ---------------------  ---------  ------  -----       |
|  09-20 13:36   jdoe    api-workers/i-0a1b2c3d asciicast  41 KB   0  [ Play ] |
|  09-19 17:02   jdoe    win-jump               guac       182 MB  2  [ Play ] |
|  09-19 09:15   asmith  bastion-01             asciicast  3 KB    1  [ Play ] |
+------------------------------------------------------------------------------+
```

### 4c. Recording player

```
+------------------------------------------------------------------------------+
| Recordings  >  jdoe on api-workers/i-0a1b2c3d  ·  ssh  ·  2026-09-20 13:36   |
+------------------------------------------------------------------------------+
|  Viewing this recording is logged.                          sha256 verified  |
|                                                                              |
|  +--------------------------------------------------------------------+      |
|  |  deploy@ip-10-0-3-17:~$ uptime                                     |      |
|  |   14:02:11 up 3:12,  1 user,  load average: 0.31, 0.28, 0.25       |      |
|  |  deploy@ip-10-0-3-17:~$ sudo systemctl status api                  |      |
|  |                                                                    |      |
|  +--------------------------------------------------------------------+      |
|  [ ▶ ]  ●━━━━━━━━━━━━━━━━━━━━━━━━○━━━━━━━━━━━━━━━━━━━━  04:12 / 12:41  1x ▼ |
|                                                                              |
|  View history                                                                |
|  2026-09-20 13:52  auditor   203.0.113.9   (you, now)                        |
|  2026-09-19 18:10  auditor2  203.0.113.4                                     |
+------------------------------------------------------------------------------+
```

Pressing Play issues the `GET /recordings/{id}/stream` request, which is the moment the view
is recorded; opening the page alone is not. The banner says so before the first byte. The
sha256 badge compares the streamed bytes with `Recording.sha256`. asciicast recordings play in
an xterm.js-based player with a scrub bar; guac recordings use the guacamole-common-js
player with the same controls. The view history is `GET /recordings/{id}/views` and updates
after the current view is inserted.

## 5. UX rules

- **No destructive action without confirmation.** Delete, terminate, trust a host key, revoke
  sessions and un-enroll an autoscaling group all confirm, naming the object and the side
  effects (sessions that will drop, policies that will disappear). Confirmations for host key
  trust and delete require typing part of the name or fingerprint.
- **Secrets are never rendered after save.** Passwords, private keys, client secrets, bind
  passwords, TOTP secrets and recovery codes are shown once at most, in the moment they are
  created, and never again. Forms show "secret set, rotated 2026-09-01" in their place.
  Generated SSH keys display the public half only.
- **Role-gated navigation.** The bundle mounts a route tree only when `/auth/me` lists the
  role. The server enforces every route regardless; the UI gating is for clarity, not
  security. Auditors do not see configuration; admins see everything, and every read of the
  audit log or a recording is logged.
- **Keyboard-first terminal.** Focus lands in the terminal, stays there, and every bar action
  has a chord listed in the help overlay. Browser-captured chords are remapped where possible.
- **Accessible contrast.** All text meets WCAG 2.2 AA contrast in both light and dark themes.
  Status is never conveyed by colour alone: healthy, changed, failed and locked always carry
  a word or glyph.
- **Say what happened.** Every blocked action explains why in one sentence (policy, time
  window, host key, no healthy instances) instead of failing silently or hiding the button.
- **One product, two densities.** The user portal is calm and sparse; the admin and auditor
  portals are dense tables. Both share the same components, type scale and bar layout so the
  session view is identical regardless of who opened it.
