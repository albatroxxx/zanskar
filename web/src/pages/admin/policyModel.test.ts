import { describe, expect, it } from 'vitest'
import type { Policy, PolicyGrant, Protocol } from '../../api/types'
import { accessLine, chipsFor, extrasLine, fromDraft, grantSummary, grantsLine, matchToRows, newGrant, policyRollup, reachLine, rowsToMatch, targetsCell, toDraft, whoSummary } from './policyModel'

const name = (id: string) => ({ t1: 'web-1', t2: 'dc-1', d1: 'orders' } as Record<string, string>)[id] ?? id

describe('chipsFor', () => {
  it('offers what a probe found, else what the OS usually serves', () => {
    expect(chipsFor('host', { capabilities: ['ssh', 'database' as never], os_family: 'linux' })).toEqual(['ssh'])
    expect(chipsFor('host', { capabilities: [], os_family: 'linux' })).toEqual(['ssh', 'vnc'])
    expect(chipsFor('host', { capabilities: [], os_family: 'windows' })).toEqual(['rdp', 'winrm', 'ssh'])
    expect(chipsFor('host', { capabilities: [], os_family: 'other' })).toEqual(['ssh', 'rdp', 'vnc', 'winrm'])
    expect(chipsFor('autoscaling', { capabilities: ['rdp'], os_family: 'windows' })).toEqual(['rdp'])
    expect(chipsFor('database', { capabilities: [], os_family: 'other' })).toEqual(['database'])
  })
})

describe('tag rows', () => {
  it('read a repeated key as any of its values, and back', () => {
    const { match } = rowsToMatch([{ key: 'env', value: 'prod' }, { key: ' env ', value: 'staging' }, { key: 'tier', value: 'web' }, { key: '', value: '' }])
    expect(match).toEqual({ env: ['prod', 'staging'], tier: ['web'] })
    expect(rowsToMatch(matchToRows(match)).match).toEqual(match)
  })

  it('refuse half a row and a value given twice', () => {
    expect(rowsToMatch([{ key: 'env', value: '' }]).error).toBe('tag env: value is empty')
    expect(rowsToMatch([{ key: '', value: 'prod' }]).error).toBe('tag 1: key is empty')
    expect(rowsToMatch([{ key: 'env', value: 'a' }, { key: 'env', value: 'a' }]).error).toBe('tag env: a is given twice')
  })
})

describe('a grant draft', () => {
  it('becomes the grant the API takes, protocols per target', () => {
    const d = toDraft(newGrant('host'))
    d.targets = { t1: ['ssh'], t2: ['rdp', 'winrm'] }
    d.tagRows = [{ key: 'env', value: 'prod' }]
    d.tagProtocols = ['ssh']
    d.access = 'approval'
    d.max = '120'
    const { grant, error } = fromDraft(d, name)
    expect(error).toBeUndefined()
    expect(grant).toEqual({
      kind: 'host', targets: [{ id: 't1', protocols: ['ssh'] }, { id: 't2', protocols: ['rdp', 'winrm'] }],
      tags: { match: { env: ['prod'] }, protocols: ['ssh'] }, access: 'approval', sign_in: 'target', require_mfa: true,
      allow_clipboard: false, allow_file_transfer: false, idle_timeout_minutes: 15, max_session_minutes: 120, time_windows: [], retention_days: null,
    })
  })

  it('names what is missing', () => {
    const d = toDraft(newGrant('host'))
    expect(fromDraft(d, name).error).toBe('choose targets, or match tags')
    d.targets = { t1: [] }
    expect(fromDraft(d, name).error).toBe('web-1 has no protocol')
    d.targets = { t1: ['ssh'] }
    d.idle = '0'
    expect(fromDraft(d, name).error).toBe('idle timeout must be 1-1440 minutes')
    d.idle = '15'
    d.retention = '4000'
    expect(fromDraft(d, name).error).toBe('keep recordings must be 1-3650 days')
  })

  it('gives a database and an application their one protocol', () => {
    const d = toDraft(newGrant('database'))
    d.targets = { d1: [] }
    expect(fromDraft(d, name).grant?.targets).toEqual([{ id: 'd1', protocols: ['database'] }])
    const app = toDraft({ ...newGrant('application'), sign_in: 'own' })
    app.targets = { a1: [] }
    expect(fromDraft(app, name).grant).toMatchObject({ targets: [{ id: 'a1', protocols: ['http'] }], sign_in: 'target' })
  })

  it('keeps its id on edit, and copies conditions for "same conditions"', () => {
    const g: PolicyGrant = { ...newGrant('host'), id: 'g1', targets: [{ id: 't1', protocols: ['ssh'] }], access: 'approval', allow_clipboard: true, idle_timeout_minutes: 30, time_windows: [{ days: ['mon'], from: '09:00', to: '18:00', tz: 'UTC' }] }
    expect(fromDraft(toDraft(g), name).grant).toEqual(g)
    const next = newGrant('database', g)
    expect(next).toMatchObject({ kind: 'database', targets: [], access: 'approval', allow_clipboard: true, idle_timeout_minutes: 30 })
    expect(next.time_windows).not.toBe(g.time_windows)
  })
})

describe('summaries', () => {
  it('say a grant on one line', () => {
    const g: PolicyGrant = { ...newGrant('host'), targets: [{ id: 't1', protocols: ['ssh'] }, { id: 't2', protocols: ['rdp', 'winrm'] }],
      tags: { match: { env: ['prod', 'staging'] }, protocols: ['ssh'] }, access: 'approval', allow_clipboard: true }
    expect(grantSummary(g, name)).toBe('Host · web-1 (SSH), dc-1 (RDP, WinRM) · env prod|staging (SSH) · Approval · MFA · clipboard · 15m')
    expect(grantSummary({ ...newGrant('database'), targets: [{ id: 'd1', protocols: ['database'] }], require_mfa: false, sign_in: 'own' }, name))
      .toBe('Database · orders · Standing · own login · 15m')
  })

  it('name the audience, and say when they cut it short', () => {
    const p = { subjects: [{ kind: 'group', id: 'g1' }, { kind: 'user', id: 'u1' }, { kind: 'user', id: 'u2' }, { kind: 'user', id: 'u3' }] } as Policy
    expect(whoSummary(p, () => 'ops', (id) => id)).toEqual({ text: 'ops · 3 users', cut: true })
    expect(whoSummary({ subjects: p.subjects.slice(0, 2) } as Policy, () => 'ops', () => 'ann')).toEqual({ text: 'ops · ann', cut: false })
    const many = { subjects: ['a', 'b', 'c', 'd'].map((id) => ({ kind: 'group', id })) } as Policy
    expect(whoSummary(many, (id) => id, () => '')).toEqual({ text: 'a, b +2', cut: true })
  })

  // ADR 0036, amended 2026-10-30: twelve grants made twelve lines. The list
  // sums them up and shows the loosest terms, because each grant admits on
  // its own: eleven grants with MFA and one without is MFA-less access.
  it('sum a policy up by its loosest terms', () => {
    const p = {
      grants: [
        { ...newGrant('host'), targets: [{ id: 't1', protocols: ['ssh'] }, { id: 't2', protocols: ['rdp'] }] },
        { ...newGrant('host'), targets: [{ id: 't1', protocols: ['vnc'] }], access: 'approval', require_mfa: false, allow_clipboard: true },
        { ...newGrant('autoscaling'), tags: { match: { env: ['test'] }, protocols: ['ssh'] }, require_mfa: false },
      ],
    } as unknown as Policy
    const r = policyRollup(p)
    expect(grantsLine(r)).toBe('3 grants · Host 2 · Autoscaling 1')
    expect(reachLine(r)).toBe('2 targets · tag env test')
    expect(accessLine(r)).toBe('Standing ×2 · Approval ×1')
    expect([r.standingNoMFA, r.approvalNoMFA]).toEqual([1, 1])
    expect(extrasLine(r)).toBe('clipboard ×1')
    const strict = policyRollup({ grants: [p.grants[0]] } as Policy)
    expect(accessLine(strict)).toBe('Standing · MFA')
    expect([strict.standingNoMFA, strict.approvalNoMFA]).toEqual([0, 0])
    expect(policyRollup({ grants: [] } as unknown as Policy).mfaAll).toBe(false)
  })

  it('cut a long target list to the first few', () => {
    const g = { ...newGrant('host'), targets: ['t1', 't2', 't3', 't4', 't5'].map((id) => ({ id, protocols: ['ssh'] as Protocol[] })) }
    expect(targetsCell(g, (id) => id)).toBe('t1 (SSH), t2 (SSH), t3 (SSH) +2')
  })
})
