import { describe as group, expect, it } from 'vitest'
import type { AuditEvent } from '../../api/types'
import { describe, detailText, humanAction, who } from './eventText'

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
    [{ action: 'session.connect', outcome: 'failure' as const, object_name: 'web-1', details: { protocol: 'ssh', reason: 'not_allowed' } }, 'was refused SSH access to web-1 (not allowed)'],
    [{ action: 'session.start', object_name: 'bob → web-1 (SSH)' }, 'opened a SSH session on web-1'],
    [{ action: 'session.end', object_name: 'bob → web-1 (SSH)', details: { reason: 'idle_timeout' } }, 'ended the SSH session on web-1 (idle timeout)'],
    [{ action: 'session.end', object_name: 'bob → win-1 (RDP)', details: { reason: 'target_lost', detail: 'Upstream error.', status: '0x0203' } }, 'ended the RDP session on win-1 (target lost: Upstream error.)'],
    [{ action: 'session.terminate', object_name: 'bob → web-1 (SSH)' }, "terminated bob's SSH session on web-1"],
    [{ action: 'session.shadow.start', object_name: 'bob → web-1 (SSH)' }, "started watching bob's SSH session on web-1"],
    [{ action: 'session.shadow.end', object_name: 'bob → web-1 (SSH)' }, "stopped watching bob's session on web-1"],
    [{ action: 'session.failover', object_name: 'bob → web-1 (SSH)' }, 'moved the SSH session on web-1 to another instance'],
    [{ action: 'recording.view', object_name: 'bob → web-1 (SSH)' }, 'played the recording of bob on web-1 (SSH)'],
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
