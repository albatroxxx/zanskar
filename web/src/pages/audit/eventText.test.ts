import { describe as group, expect, it } from 'vitest'
import type { AuditEvent } from '../../api/types'
import { describe, detailText, humanAction, typeLabel, who } from './eventText'

const event = (over: Partial<AuditEvent>): AuditEvent => ({
  id: 1, ts: '2026-10-02T14:40:40Z', actor_user_id: 'u1', actor_username: 'root', actor_ip: '127.0.0.1',
  action: 'user.login', object_type: '', object_id: '', outcome: 'success', details: {}, prev_hash: '', hash: '',
  ...over,
})

// A hex id fragment such as d2091e4b in a sentence is what #120 removed.
const hexId = /\b[0-9a-f]{8,}\b/

group('access request events read as who asked for what', () => {
  const req = (action: string, object_name?: string) =>
    event({ action, object_type: 'access_request', object_id: 'd2091e4b9c', object_name })

  it.each([
    ['access.request.create', 'requested SSH access to web-1'],
    ['access.request.approve', "approved bob's request for SSH access to web-1"],
    ['access.request.deny', "denied bob's request for SSH access to web-1"],
    ['access.request.revoke', "revoked bob's SSH access to web-1"],
    ['access.grant.expire', "ended bob's SSH access to web-1 (time limit reached)"],
  ])('%s', (action, want) => {
    expect(describe(req(action, 'bob → web-1 (SSH)'))).toBe(want)
  })

  it('names the database protocol in words, not as a code', () => {
    expect(describe(req('access.request.deny', 'bob → orders-db (database)'))).toBe("denied bob's request for database access to orders-db")
  })

  it.each(['access.request.create', 'access.request.approve', 'access.request.deny', 'access.request.revoke', 'access.grant.expire'])(
    '%s without a label still reads as words',
    (action) => {
      const text = describe(req(action))
      expect(text).not.toMatch(hexId)
      expect(text.length).toBeGreaterThan(0)
    },
  )
})

group('command line events', () => {
  it.each([
    [{ action: 'cli.unlock' }, 'opened the command line'],
    [{ action: 'cli.unlock', details: { recovery_code_used: true } }, 'opened the command line with a recovery code'],
    [{ action: 'cli.unlock', outcome: 'failure', details: { reason: 'wrong code' } }, 'failed to open the command line (wrong code)'],
    [{ action: 'cli.unlock', outcome: 'failure', details: { reason: 'code already used' } }, 'failed to open the command line (code already used)'],
    [{ action: 'user.mfa.verify', outcome: 'failure', details: { reason: 'code_reused' } }, 'failed the second factor (a code already used)'],
    [{ action: 'cli.command', details: { line: 'sessions --live', result: 'ok' } }, 'ran “sessions --live” on the command line'],
    [{ action: 'cli.command', details: { line: 'restart', result: 'confirm_requested' } }, 'ran “restart” on the command line (asked to confirm)'],
    [{ action: 'cli.command', outcome: 'failure', details: { line: 'rm -rf /', result: 'unknown' } }, 'ran “rm -rf /” on the command line (not a command)'],
  ] as const)('%o', (over, want) => {
    expect(describe(event(over as Partial<AuditEvent>))).toBe(want)
  })
})

group('who', () => {
  it('names the actor', () => {
    expect(who(event({}))).toEqual({ name: 'root', system: false })
  })
  it('calls an unnamed account a deleted user, not an id fragment', () => {
    expect(who(event({ actor_username: undefined, actor_user_id: '9ddd1eccab' }))).toEqual({ name: 'deleted user', system: false })
  })
  it('tells the gateway apart from the system', () => {
    expect(who(event({ actor_username: undefined, actor_user_id: '', actor_ip: 'sync' })).name).toBe('gateway')
    expect(who(event({ actor_username: undefined, actor_user_id: '', actor_ip: 'system' })).name).toBe('system')
  })
})

group('humanAction', () => {
  it('uses the label for a known code', () => {
    expect(humanAction('access.request.approve')).toBe('Access request approved')
  })
  it('turns an unknown code into words', () => {
    expect(humanAction('tls.cert_upload')).toBe('TLS cert upload')
  })
})

group('detailText', () => {
  it('shows a timestamp as a date and time, keeping the exact value', () => {
    const d = detailText('2026-10-04T15:16:06.752946Z')
    expect(d.text).not.toContain('T15:16')
    expect(d.title).toBe('2026-10-04T15:16:06.752946Z')
  })
  it('leaves other values as they are', () => {
    expect(detailText(60)).toEqual({ text: '60' })
    expect(detailText('database')).toEqual({ text: 'database' })
  })
})

// Review finding F1: the failed sign-in branch replaced by "signed in" passed
// all 26 tests, which covered none of the sign-in, session or recording
// sentences. These are what an auditor reads; each branch is pinned.
group('sign-in, session and recording events read as what happened', () => {
  it.each([
    [{ action: 'user.login', outcome: 'failure' as const, details: { username: 'bob', reason: 'bad_password' } }, 'failed to sign in as bob (bad password)'],
    [{ action: 'user.login', outcome: 'failure' as const, details: { reason: 'locked' } }, 'failed to sign in (locked)'],
    [{ action: 'user.login', outcome: 'failure' as const }, 'failed to sign in'],
    [{ action: 'user.login', details: { stage: 'password', next: 'mfa_enrollment' } }, 'entered a valid password; authenticator enrollment pending'],
    [{ action: 'user.login', details: { stage: 'password' } }, 'entered a valid password; second factor pending'],
    [{ action: 'user.login', details: { mfa: 'totp' } }, 'signed in with TOTP'],
    [{ action: 'user.login', details: { mfa: 'none' } }, 'signed in'],
    [{ action: 'user.login' }, 'signed in'],
    [{ action: 'user.logout' }, 'signed out'],
    [{ action: 'user.mfa.enroll' }, 'started enrolling an authenticator'],
    [{ action: 'user.mfa.confirm' }, 'enrolled an authenticator'],
    [{ action: 'user.mfa.confirm', outcome: 'failure' as const }, 'failed to confirm an authenticator'],
    [{ action: 'user.mfa.verify' }, 'passed the second factor'],
    [{ action: 'session.connect', object_name: 'web-1', details: { protocol: 'ssh' } }, 'requested SSH access to web-1'],
    [{ action: 'session.connect', object_name: 'win-1', details: { protocol: 'winrm' } }, 'requested WinRM access to win-1'],
    [{ action: 'session.connect', outcome: 'failure' as const, object_name: 'web-1', details: { protocol: 'ssh', reason: 'not_allowed' } }, 'was refused SSH access to web-1 (not allowed)'],
    [{ action: 'session.start', object_name: 'bob → web-1 (SSH)' }, 'opened an SSH session on web-1'],
    [{ action: 'session.start', object_name: 'bob → app (HTTP)' }, 'opened an HTTP session on app'],
    [{ action: 'session.start', object_name: 'bob → win-1 (RDP)' }, 'opened an RDP session on win-1'],
    [{ action: 'session.start', object_name: 'bob → mac (VNC)' }, 'opened a VNC session on mac'],
    [{ action: 'session.start', object_name: 'bob → db (PostgreSQL)' }, 'opened a PostgreSQL session on db'],
    [{ action: 'session.end', object_name: 'bob → web-1 (SSH)', details: { reason: 'idle_timeout' } }, 'ended the SSH session on web-1 (idle timeout)'],
    [{ action: 'session.end', object_name: 'bob → win-1 (RDP)', details: { reason: 'target_lost', detail: 'Upstream error.', status: '0x0203' } }, 'ended the RDP session on win-1 (target lost: Upstream error.)'],
    [{ action: 'session.terminate', object_name: 'bob → web-1 (SSH)' }, "terminated bob's SSH session on web-1"],
    [{ action: 'session.shadow.start', object_name: 'bob → web-1 (SSH)' }, "started watching bob's SSH session on web-1"],
    [{ action: 'session.shadow.end', object_name: 'bob → web-1 (SSH)' }, "stopped watching bob's session on web-1"],
    [{ action: 'session.failover', object_name: 'bob → web-1 (SSH)' }, 'moved the SSH session on web-1 to another instance'],
    [{ action: 'recording.view', object_name: 'bob → web-1 (SSH)' }, 'played the recording of bob on web-1 (SSH)'],
    // Live, 2026-11-11: "search recording", not a sentence, the term only in the raw details.
    [{ action: 'recording.search', details: { q: 'ls', in: 'commands', count: 1 } }, "searched the recordings' commands for “ls” (1 match)"],
    [{ action: 'recording.search', details: { q: 'permission denied', in: 'output', count: 0 } }, "searched the recordings' output for “permission denied” (0 matches)"],
    [{ action: 'audit.read' }, 'viewed the audit log'],
  ])('%j', (over, want) => {
    expect(describe(event(over as Partial<AuditEvent>))).toBe(want)
  })

  it('a failed sign-in never reads as a success', () => {
    const text = describe(event({ action: 'user.login', outcome: 'failure', details: { username: 'bob' } }))
    expect(text).not.toMatch(/^signed in/)
    expect(text).toMatch(/^failed to sign in/)
  })
})

// 2026-11-04 live QA of 1.18.0: the gateway's own actions and the mail server
// fell to the generic "<verb> <type> <name>" and read "boot request system
// gateway", "images remove system gateway", "updated system gateway", "export
// gateway" and "deleted email server 1".
group('install, gateway, configuration and mail server events read as what happened', () => {
  const sys = { object_type: 'system', object_id: 'gateway' }
  const mail = { object_type: 'email_server', object_id: '1' }
  const failed = { outcome: 'failure' as const }
  // The request records the variables as {NAME: value}; the helper's answer
  // lists the names it changed.
  const asked = { request_id: 'r1', changes: { ZANSKAR_LISTEN_ADDR: ':443', ZANSKAR_TLS_MODE: 'managed' }, tls_mode: 'managed', wait_minutes: 5, live_sessions: 0 }

  const cases: [string, Partial<AuditEvent>, string][] = [
    ['an install settings change asked for names its variables', { action: 'settings.boot_request', ...sys, details: asked }, 'requested an install settings change (ZANSKAR_LISTEN_ADDR, ZANSKAR_TLS_MODE)'],
    ['a list of changed names reads the same', { action: 'settings.boot_request', ...sys, details: { changed: ['ZANSKAR_TLS_HOSTS'] } }, 'requested an install settings change (ZANSKAR_TLS_HOSTS)'],
    ['no names, no brackets', { action: 'settings.boot_request', ...sys }, 'requested an install settings change'],
    ['no brackets for a list that is not names', { action: 'settings.boot_request', ...sys, details: { changes: [1, ''] } }, 'requested an install settings change'],
    ['a change applied', { action: 'settings.boot_apply', ...sys, details: { request_id: 'r1', state: 'applied', changed: ['ZANSKAR_TLS_MODE'] } }, 'applied an install settings change'],
    ['a change the gateway never saw applied', { action: 'settings.boot_apply', ...sys, ...failed, details: { request_id: 'r1', error: 'the helper did not answer within 10m0s' } }, 'failed to apply an install settings change'],
    ['a change rolled back', { action: 'settings.boot_apply', ...sys, ...failed, details: { request_id: 'r1', state: 'rolled_back', changed: ['ZANSKAR_TLS_MODE'], message: 'did not come back' } }, 'failed to apply an install settings change: rolled back'],
    ['an update asked for, from a version to a version', { action: 'system.update', ...sys, details: { version: '1.19.0', from: '1.18.0' } }, 'requested a gateway update to 1.19.0'],
    ['an update with no version recorded', { action: 'system.update', ...sys }, 'requested a gateway update'],
    ['an update that failed', { action: 'system.update', ...sys, ...failed, details: { version: '1.19.0', error: 'the installer did not finish' } }, 'failed to update the gateway to 1.19.0'],
    ['an update that failed with no version', { action: 'system.update', ...sys, ...failed }, 'failed to update the gateway'],
    ['a restart', { action: 'system.restart', ...sys }, 'requested a gateway restart'],
    ['a restart cancelled', { action: 'system.restart_cancel', ...sys }, 'cancelled the gateway restart'],
    ['a reboot', { action: 'system.reboot', ...sys }, 'requested a host reboot'],
    ['a power-off', { action: 'system.poweroff', ...sys }, 'requested a host power-off'],
    ['old images removed', { action: 'system.images_remove', ...sys, actor_user_id: '', actor_username: undefined, actor_ip: 'system', details: { images: ['zanskar-browser:1.17.0'] } }, 'removed old images'],
    ['the configuration exported', { action: 'config.export', object_type: 'gateway', object_id: '', details: { groups: 2, targets: 5, policies: 3 } }, 'exported the configuration'],
    ['the configuration imported', { action: 'config.import', object_type: 'gateway', object_id: '', details: { changed: { targets: 2 }, failed: '' } }, 'imported the configuration'],
    ['the email server set', { action: 'notify.email_server.update', ...mail, details: { host: 'smtp.example.test', port: 587 } }, 'set the email server'],
    ['the email server removed', { action: 'notify.email_server.delete', ...mail }, 'removed the email server'],
    ['the email server tested', { action: 'notify.email_server.test', ...mail, details: { to: 'ops@example.test' } }, 'tested the email server'],
    ['the email server test that failed', { action: 'notify.email_server.test', ...mail, ...failed, details: { to: 'ops@example.test' } }, 'failed to test the email server'],
  ]

  it.each(cases)('%s', (_name, over, want) => {
    expect(describe(event(over))).toBe(want)
  })

  // The generic reading is what these replaced: raw action words, the type
  // and the object's id. None of it may come back for these actions.
  const raw = /boot |images remove|system gateway|gateway gateway|email server \d|\b1$|^(export|import|restart|reboot|poweroff)\b/
  it.each(cases)('%s: no raw action words or object id', (_name, over) => {
    expect(describe(event(over))).not.toMatch(raw)
  })

  // The review finding of the sign-in sentences, for these: a failure must
  // not read as the thing having happened.
  const config = { object_type: 'gateway', object_id: '' }
  const everyAction: [string, Partial<AuditEvent>][] = [
    ['settings.boot_request', sys], ['settings.boot_apply', sys], ['system.update', sys], ['system.restart', sys],
    ['system.restart_cancel', sys], ['system.reboot', sys], ['system.poweroff', sys], ['system.images_remove', sys],
    ['config.export', config], ['config.import', config],
    ['notify.email_server.update', mail], ['notify.email_server.delete', mail], ['notify.email_server.test', mail],
  ]
  it.each(everyAction)('%s that failed reads as a failure', (action, where) => {
    expect(describe(event({ ...where, action, ...failed }))).toMatch(/^failed to /)
  })

  it('names the object types the Object-type filter listed raw', () => {
    expect(typeLabel.email_server).toBe('email server')
    expect(typeLabel.retention_policy).toBe('retention policy')
    expect(typeLabel.cli).toBe('command line')
  })

  it('reads a retention policy change by its type in words, as before the label', () => {
    expect(describe(event({ action: 'retention.policy.update', object_type: 'retention_policy', object_id: 'default' }))).toMatch(/^updated retention policy\b/)
  })

  // 2026-11-04, live walkthrough of 1.18.3.
  it('keeps a setting key whole: it is the name, not an id to shorten', () => {
    expect(describe(event({ action: 'settings.update', object_type: 'setting', object_id: 'display.theme' }))).toBe('updated setting display.theme')
    expect(describe(event({ action: 'settings.reset', object_type: 'setting', object_id: 'login_banner' }))).toBe('reset setting login_banner')
    expect(describe(event({ action: 'target.create', object_type: 'target', object_id: 'd2091e4b9c3a4f10a1b2c3d4e5f60718' }))).toBe('created target d2091e4b')
  })

  it('names what a refused create asked for, and why it was refused', () => {
    expect(describe(event({ action: 'target.create', object_type: 'target', outcome: 'failure', details: { name: 'qa-walk-app', reason: 'address_forbidden' } })))
      .toBe('failed to create target qa-walk-app (address forbidden)')
    // A failure that has an object keeps naming that object; a success never reads a reason.
    expect(describe(event({ action: 'target.update', object_type: 'target', object_id: 't1', object_name: 'web-1', outcome: 'failure' }))).toBe('failed to update target web-1')
  })

  it('reads a completed access review as reviewed', () => {
    expect(describe(event({ action: 'policy.review', object_type: 'policy', object_id: 'p1', object_name: 'prod-ssh' }))).toBe('reviewed policy prod-ssh')
  })

  it('says a deleted account once: the delete event does not repeat "(deleted)"', () => {
    expect(describe(event({ action: 'user.delete', object_type: 'user', object_id: 'u1', object_name: 'alice (deleted)' }))).toBe('deleted user alice')
    // Other events by or about a gone account keep the mark.
    expect(describe(event({ action: 'user.update', object_type: 'user', object_id: 'u1', object_name: 'alice (deleted)' }))).toBe('updated user alice (deleted)')
  })
})
