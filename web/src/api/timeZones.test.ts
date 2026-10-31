import { describe, expect, it } from 'vitest'
import { canonicalZone, describeZone, searchZones, zoneOptions, zonesFrom, zoneText } from './timeZones'

// A winter instant: New York on standard time, no daylight saving anywhere
// the assertions look.
const jan = Date.UTC(2026, 0, 15, 12)

// 2026-10-31: Chromium lists 418 zones under ICU's older names (Asia/Calcutta,
// Europe/Kiev) and without UTC, the setting's default.
describe('the zones offered', () => {
  it('always has UTC, and each zone once under its current name, west to east', () => {
    const ids = zonesFrom(['Asia/Calcutta', 'Asia/Kolkata', 'Europe/Kiev', 'America/New_York'], jan).map((o) => o.id)
    expect(ids).toEqual(['America/New_York', 'UTC', 'Europe/Kyiv', 'Asia/Kolkata'])
    expect(canonicalZone('Asia/Calcutta')).toBe('Asia/Kolkata')
    expect(canonicalZone('Asia/Tokyo')).toBe('Asia/Tokyo')
  })

  it('describes a zone by offset, city, region and name', () => {
    const k = describeZone('Asia/Calcutta', jan)!
    expect(k).toMatchObject({ id: 'Asia/Kolkata', city: 'Kolkata', region: 'Asia', offset: 'UTC+05:30', offsetMinutes: 330, older: 'Asia/Calcutta' })
    expect(zoneText(k)).toBe(`UTC+05:30 · Kolkata (Asia) · ${k.name}`)
    expect(describeZone('America/Argentina/Buenos_Aires', jan)).toMatchObject({ city: 'Buenos Aires', region: 'America › Argentina', offset: 'UTC-03:00' })
    expect(describeZone('UTC', jan)).toMatchObject({ city: 'UTC', region: '', offset: 'UTC+00:00' })
    // A name that only repeats the offset is left out.
    expect(describeZone('Etc/GMT-14', jan)?.name).toBe('')
    expect(describeZone('Not/A_Zone', jan)).toBeNull()
  })

  it('adds the saved zone when the browser does not list it', () => {
    const all = zoneOptions('Etc/GMT+5')
    expect(all.some((o) => o.id === 'Etc/GMT+5')).toBe(true)
    expect(all.some((o) => o.id === 'UTC')).toBe(true)
    expect(all.length).toBeGreaterThan(300)
  })
})

describe('searching the zones', () => {
  const all = zonesFrom(['Asia/Calcutta', 'Asia/Tokyo', 'Europe/Kiev', 'Europe/London', 'America/New_York', 'America/Argentina/Buenos_Aires'], jan)
  const find = (q: string) => searchZones(all, q).map((o) => o.id)

  it('finds by city, older name, long name, offset and several words', () => {
    expect(find('kolkata')).toEqual(['Asia/Kolkata'])
    expect(find('Calcutta')).toEqual(['Asia/Kolkata'])
    expect(find('india')).toEqual(['Asia/Kolkata'])
    expect(find('+5:30')).toEqual(['Asia/Kolkata'])
    expect(find('5:30')).toEqual(['Asia/Kolkata'])
    expect(find('utc+05:30')).toEqual(['Asia/Kolkata'])
    expect(find('kiev')).toEqual(['Europe/Kyiv'])
    expect(find('buenos aires')).toEqual(['America/Argentina/Buenos_Aires'])
    expect(find('Buenos_Aires')).toEqual(['America/Argentina/Buenos_Aires'])
    expect(find('america new')).toEqual(['America/New_York'])
    expect(find('europe')).toEqual(['Europe/London', 'Europe/Kyiv'])
  })

  it('shows everything for an empty search and nothing for a stranger', () => {
    expect(searchZones(all, '  ')).toHaveLength(all.length)
    expect(find('atlantis')).toEqual([])
  })
})
