import { describe, expect, it } from 'vitest'
import { fromDraft, grantSummary, newGrant, toDraft } from './policyModel'

const nameOf = (id: string) => id

// ADR 0049: an approval grant names who decides; a standing grant sends
// none, whatever the editor still holds for the switch back.
describe('a grant\'s approvers', () => {
  it('round-trips through the draft and is sent for an approval grant alone', () => {
    const g = newGrant('host')
    g.targets = [{ id: 't1', protocols: ['ssh'] }]
    g.access = 'approval'
    g.approvers = [{ kind: 'group', id: 'g1' }, { kind: 'user', id: 'u1' }]
    const d = toDraft(g)
    expect(d.approverGroups).toEqual(['g1'])
    expect(d.approverUsers).toEqual(['u1'])
    expect(fromDraft(d, nameOf).grant?.approvers).toEqual([{ kind: 'group', id: 'g1' }, { kind: 'user', id: 'u1' }])
    const standing = fromDraft({ ...d, access: 'standing' }, nameOf).grant!
    expect(standing.approvers).toBeUndefined()
    expect('approvers' in standing).toBe(false)
  })

  it('sends no approvers key when none is named', () => {
    const d = toDraft({ ...newGrant('host'), targets: [{ id: 't1', protocols: ['ssh'] }], access: 'approval' })
    expect('approvers' in fromDraft(d, nameOf).grant!).toBe(false)
  })

  it('refuses more than 32', () => {
    const d = toDraft({ ...newGrant('host'), targets: [{ id: 't1', protocols: ['ssh'] }], access: 'approval' })
    d.approverUsers = Array.from({ length: 33 }, (_, i) => `u${i}`)
    expect(fromDraft(d, nameOf).error).toBe('at most 32 approvers')
  })

  it('is a condition "same conditions" keeps, and the summary counts it', () => {
    const from = { ...newGrant('host'), access: 'approval' as const, approvers: [{ kind: 'group' as const, id: 'g1' }] }
    expect(newGrant('database', from).approvers).toEqual([{ kind: 'group', id: 'g1' }])
    expect(newGrant('database', { ...from, access: 'standing' }).approvers).toBeUndefined()
    expect(grantSummary({ ...from, targets: [{ id: 't1', protocols: ['ssh'] }] }, nameOf)).toContain('Approval · 1 approver')
    expect(grantSummary({ ...from, targets: [{ id: 't1', protocols: ['ssh'] }], approvers: [{ kind: 'group', id: 'g1' }, { kind: 'user', id: 'u1' }] }, nameOf)).toContain('2 approvers')
  })
})
