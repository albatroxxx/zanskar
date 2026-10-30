import { describe, expect, it } from 'vitest'
import { consoleZone, fmtTime, protocolName, setDisplayZone, zoneLabel, zonedInputToISO, zoneOffsetMs } from './format'

// Protocols read as names, not codes: acronyms stay acronyms, WinRM keeps its
// spelling, and "database" is a word (the console used to show DATABASE).
describe('protocolName', () => {
  it.each([
    ['ssh', 'SSH'],
    ['rdp', 'RDP'],
    ['vnc', 'VNC'],
    ['winrm', 'WinRM'],
    ['database', 'database'],
  ])('%s reads as %s', (code, want) => {
    expect(protocolName(code)).toBe(want)
  })
})

// 2026-10-30: every time in the console follows the console's time zone,
// the gateway host's by default, and a filter typed in it means it.
describe('the console time zone', () => {
  it('formats times in the zone set, and ignores one it does not know', () => {
    const iso = '2026-10-30T12:00:00Z'
    setDisplayZone('Asia/Kolkata')
    expect(consoleZone()).toBe('Asia/Kolkata')
    expect(fmtTime(iso)).toMatch(/17:30|5:30/)
    setDisplayZone('America/New_York')
    expect(fmtTime(iso)).toMatch(/08:00|8:00/)
    setDisplayZone('Mars/Olympus')
    expect(consoleZone()).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone)
    setDisplayZone(undefined)
  })

  it('knows a zone\'s offset, daylight saving included', () => {
    expect(zoneOffsetMs(Date.parse('2026-10-30T12:00:00Z'), 'Asia/Kolkata')).toBe(5.5 * 3600_000)
    expect(zoneLabel(Date.parse('2026-07-01T12:00:00Z'), 'America/New_York')).toBe('UTC-04:00')
    expect(zoneLabel(Date.parse('2026-12-01T12:00:00Z'), 'America/New_York')).toBe('UTC-05:00')
    expect(zoneLabel(Date.parse('2026-12-01T12:00:00Z'), 'UTC')).toBe('UTC+00:00')
  })

  it('reads a typed date and time in the zone', () => {
    expect(zonedInputToISO('2026-10-30T17:30', 'Asia/Kolkata')).toBe('2026-10-30T12:00:00.000Z')
    expect(zonedInputToISO('2026-07-01T08:00', 'America/New_York')).toBe('2026-07-01T12:00:00.000Z')
    expect(zonedInputToISO('2026-12-01T07:00', 'America/New_York')).toBe('2026-12-01T12:00:00.000Z')
    // The morning the clocks go back, after the change.
    expect(zonedInputToISO('2026-11-01T03:00', 'America/New_York')).toBe('2026-11-01T08:00:00.000Z')
    expect(zonedInputToISO('not a time', 'UTC')).toBe('')
  })
})
