import { describe as group, expect, it } from 'vitest'
import type { AuditEvent } from '../../api/types'
import { describe, humanAction, who } from './eventText'

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
    expect(describe(req('access.request.deny', 'bob → orders-db (DATABASE)'))).toBe("denied bob's request for database access to orders-db")
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
