import { describe, expect, it } from 'vitest'
import { integrityChecks } from './dashboardChecks'

const base = {
  audit_chain: { at: '2026-10-31T09:00:00Z', intact: true, checked: 120, problems: 0 },
  recordings_lost_7d: 0,
  directories: { listed: 1, failing: 0, not_run: 0, held_back: 0 },
  export: { sinks: 1, behind: 3 },
}
const by = (i: Parameters<typeof integrityChecks>[0]) => Object.fromEntries(integrityChecks(i).map((c) => [c.label, c]))

// 2026-10-31: the integrity row says whether the evidence is whole.
describe('integrityChecks', () => {
  it('reads all well as ok, each line opening its page', () => {
    const c = by(base)
    expect(Object.values(c).map((x) => x.state)).toEqual(['ok', 'ok', 'ok', 'ok', 'ok'])
    expect(integrityChecks(base, 41, '/admin/events?range=24h').find((x) => x.label === 'Audit log')).toMatchObject({ text: '41 events in 24 hours', to: '/admin/events?range=24h' })
    expect(c['Audit chain'].text).toMatch(/^Intact · checked /)
    expect(c['Recordings']).toMatchObject({ text: 'None lost in 7 days', to: '/admin/recordings' })
    expect(c['Identity providers']).toMatchObject({ text: 'In sync', to: '/admin/identity-providers' })
    expect(c['SIEM export']).toMatchObject({ text: 'Up to date', to: '/admin/logs' })
  })

  it('never calls an unchecked chain intact, and names what is wrong', () => {
    expect(by({ ...base, audit_chain: null })['Audit chain']).toMatchObject({ text: 'Not checked yet', state: 'unknown' })
    expect(by({ ...base, audit_chain: { ...base.audit_chain, intact: false, problems: 2 } })['Audit chain']).toMatchObject({ state: 'danger' })
    expect(by({ ...base, audit_chain: { ...base.audit_chain, intact: false, error: 'disk' } })['Audit chain'].state).toBe('warn')
    const lost = by({ ...base, recordings_lost_7d: 2 })['Recordings']
    expect(lost).toMatchObject({ text: '2 lost in 7 days', state: 'danger' })
    expect(lost.to).toBe('/admin/events?action=recording.lost&outcome=failure&range=7d')
  })

  it('reads the listings and the export by what matters most', () => {
    const dir = (d: Partial<typeof base.directories>) => by({ ...base, directories: { ...base.directories, ...d } })['Identity providers']
    expect(dir({ listed: 0 })).toMatchObject({ text: 'None listed on a schedule', state: 'unknown' })
    expect(dir({ failing: 1, held_back: 4 })).toMatchObject({ text: '1 failing', state: 'danger' })
    expect(dir({ held_back: 1 })).toMatchObject({ text: '1 account held back', state: 'warn' })
    expect(dir({ not_run: 2 })).toMatchObject({ text: '2 not run yet', state: 'unknown' })
    expect(by({ ...base, export: { sinks: 0, behind: 0 } })['SIEM export']).toMatchObject({ text: 'Not configured', state: 'unknown' })
    expect(by({ ...base, export: { sinks: 2, behind: 950 } })['SIEM export']).toMatchObject({ text: '950 events behind', state: 'warn' })
  })
})
