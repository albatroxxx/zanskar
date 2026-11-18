import { describe, expect, it } from 'vitest'
import type { AccessRequest } from '../../api/types'
import { approverNames, decided } from './requests'

const base: AccessRequest = {
  id: 'r1', user_id: 'u1', username: 'bob', target_id: 't1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy',
  requested_minutes: 60, status: 'approved', state: 'approved', approver_username: 'ana', decided_at: '2026-11-16T10:05:00Z',
  created_at: '2026-11-16T10:00:00Z', updated_at: '2026-11-16T10:05:00Z',
}

// Review R9: the linked request's sentence reads the gateway's state (ADR
// 0047), so an approval past its window says it has expired, not that it
// was approved; review R3: an approver since deleted shows as their id.
describe('requests', () => {
  it('says a lapsed approval has expired, from its state', () => {
    expect(decided({ ...base, state: 'expired' })).toBe("bob's request for web-1 has expired.")
    expect(decided(base)).toContain('was already approved by ana')
  })

  it('names approvers, and falls back to the id of one who is gone', () => {
    expect(approverNames({ ...base, approvers: [{ kind: 'group', id: 'g1', name: 'ops' }, { kind: 'user', id: 'u-gone' }] })).toBe('ops, u-gone')
    expect(approverNames({ ...base, approvers: [] })).toBe('—')
  })
})
