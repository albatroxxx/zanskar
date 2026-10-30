import { describe, expect, it } from 'vitest'
import type { Policy, PolicyGrant } from '../../api/types'
import { chipsFor, fromDraft, grantSummary, matchToRows, newGrant, rowsToMatch, toDraft, whoSummary } from './policyModel'

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

  it('name the audience', () => {
    const p = { subjects: [{ kind: 'group', id: 'g1' }, { kind: 'user', id: 'u1' }, { kind: 'user', id: 'u2' }, { kind: 'user', id: 'u3' }] } as Policy
    expect(whoSummary(p, () => 'ops', (id) => id)).toBe('ops, 3 users')
    expect(whoSummary({ subjects: p.subjects.slice(0, 2) } as Policy, () => 'ops', () => 'ann')).toBe('ops, ann')
  })
})
