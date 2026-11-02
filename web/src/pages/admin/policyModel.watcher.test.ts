import { describe, expect, it } from 'vitest'
import { fromDraft, grantSummary, newGrant, toDraft, watchable } from './policyModel'

// 2026-11-03, idea 7 (ADR 0042): a second person watching is a host or
// autoscaling grant's switch; it travels with the grant and says so.
describe('four eyes in a grant', () => {
  it('is offered on hosts and autoscaling groups only', () => {
    expect(watchable('host')).toBe(true)
    expect(watchable('autoscaling')).toBe(true)
    expect(watchable('database')).toBe(false)
    expect(watchable('application')).toBe(false)
  })

  it('is sent when on, and never for a kind that cannot hold a session', () => {
    const d = toDraft({ ...newGrant('host'), targets: [{ id: 't1', protocols: ['ssh'] }], require_watcher: true })
    expect(d.require_watcher).toBe(true)
    expect(fromDraft(d, (id) => id).grant?.require_watcher).toBe(true)
    const db = { ...toDraft({ ...newGrant('database'), targets: [{ id: 'd1', protocols: ['database'] }] }), require_watcher: true }
    expect(fromDraft(db, (id) => id).grant?.require_watcher).toBeUndefined()
  })

  it('is named in the grant\'s summary, and carried to a grant of another kind only where it applies', () => {
    const g = { ...newGrant('host'), targets: [{ id: 't1', protocols: ['ssh' as const] }], require_watcher: true }
    expect(grantSummary(g, (id) => id)).toContain('four eyes')
    expect(newGrant('autoscaling', g).require_watcher).toBe(true)
    expect(newGrant('database', g).require_watcher).toBeUndefined()
  })
})
