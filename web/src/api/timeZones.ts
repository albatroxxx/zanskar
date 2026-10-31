// The time zones the console offers (Settings › Display, 2026-10-31): every
// zone the browser knows, under the names people use today, each with its
// offset and a readable name, and a search over all of them.
import { zoneLabel, zoneOffsetMs } from './format'

/** One zone in the picker. */
export interface ZoneOption {
  /** The IANA name that is saved: Asia/Kolkata. */
  id: string
  /** Its city, as people write it: Kolkata. */
  city: string
  /** The rest of the name: Asia; America › Argentina. Empty for UTC. */
  region: string
  /** The offset from UTC today: UTC+05:30. */
  offset: string
  offsetMinutes: number
  /** India Standard Time; empty when the browser knows only the offset. */
  name: string
  /** The zone's older name, when the browser uses one: Asia/Calcutta. */
  older?: string
  /** What a search looks in, lower case. */
  haystack: string
}

// Chromium's list (ICU's) still uses names the tz database has replaced.
// The gateway accepts either (Go's tzdata keeps the old ones as links); the
// console offers and saves the one people know now. A name missing here
// still works, it only reads as the browser lists it.
const modern: Record<string, string> = {
  'Africa/Asmera': 'Africa/Asmara',
  'America/Buenos_Aires': 'America/Argentina/Buenos_Aires',
  'America/Godthab': 'America/Nuuk',
  'America/Indianapolis': 'America/Indiana/Indianapolis',
  'America/Louisville': 'America/Kentucky/Louisville',
  'Asia/Calcutta': 'Asia/Kolkata',
  'Asia/Katmandu': 'Asia/Kathmandu',
  'Asia/Rangoon': 'Asia/Yangon',
  'Asia/Saigon': 'Asia/Ho_Chi_Minh',
  'Atlantic/Faeroe': 'Atlantic/Faroe',
  'Europe/Kiev': 'Europe/Kyiv',
}
const older: Record<string, string> = Object.fromEntries(Object.entries(modern).map(([was, now]) => [now, was]))

/** canonicalZone gives a zone its current name: Asia/Calcutta is Asia/Kolkata. */
export function canonicalZone(id: string): string {
  return modern[id] ?? id
}

/** browserZones is every zone the browser lists; none in one without the list. */
export function browserZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
  try {
    return intl.supportedValuesOf?.('timeZone') ?? []
  } catch {
    return []
  }
}

/** browserZone is the zone this browser runs in, under its current name. */
export function browserZone(): string {
  return canonicalZone(Intl.DateTimeFormat().resolvedOptions().timeZone)
}

/** zoneName is the zone's long name in words, or empty when the browser has
 *  only "GMT+05:30" for it, which the offset already says. A generic name
 *  ("Eastern Time") does not change with daylight saving; older browsers
 *  know only the specific one. */
function zoneName(id: string, at: Date): string {
  let parts: Intl.DateTimeFormatPart[]
  try {
    parts = new Intl.DateTimeFormat('en-US', { timeZone: id, timeZoneName: 'longGeneric' }).formatToParts(at)
  } catch {
    parts = new Intl.DateTimeFormat('en-US', { timeZone: id, timeZoneName: 'long' }).formatToParts(at)
  }
  const name = parts.find((p) => p.type === 'timeZoneName')?.value ?? ''
  return /^(GMT|UTC)([+\-−]|$)/.test(name) ? '' : name
}

const words = (s: string) => s.replace(/_/g, ' ')

/** describeZone is one zone as the picker shows it, its offset as at now;
 *  null for a name the browser does not know. */
export function describeZone(zone: string, now: number = Date.now()): ZoneOption | null {
  const id = canonicalZone(zone)
  let name: string
  try {
    name = zoneName(id, new Date(now))
  } catch {
    return null
  }
  const offsetMinutes = Math.round(zoneOffsetMs(now, id) / 60000)
  const offset = zoneLabel(now, id)
  const segs = id.split('/')
  const city = words(segs[segs.length - 1])
  const region = segs.slice(0, -1).map(words).join(' › ')
  // "+5:30" and "5:30" find UTC+05:30 as well as "+05:30" does.
  const short = offset.replace(/^UTC([+-])0?/, '$1')
  const haystack = [id, words(id).replace(/\//g, ' '), city, region, name, offset, offset.slice(3), short, older[id] ?? '', older[id] ? words(older[id]) : '']
    .join(' ')
    .toLowerCase()
  return { id, city, region, offset, offsetMinutes, name, older: older[id], haystack }
}

/** zonesFrom lists ids, UTC always among them, each once under its current
 *  name, west to east and then by city. */
export function zonesFrom(ids: string[], now: number): ZoneOption[] {
  const unique = new Set(['UTC', ...ids.map(canonicalZone)])
  const out: ZoneOption[] = []
  for (const id of unique) {
    const o = describeZone(id, now)
    if (o) out.push(o)
  }
  return out.sort((a, b) => a.offsetMinutes - b.offsetMinutes || a.city.localeCompare(b.city))
}

// Built once per page, the first time the list opens: four hundred zones'
// formatters are not free. Offsets are today's: London reads UTC+00:00 in
// winter and UTC+01:00 in summer.
let cached: ZoneOption[] | null = null

/** zoneOptions is every zone the browser knows, with the given one (the
 *  saved value) added when the browser does not list it. */
export function zoneOptions(current?: string): ZoneOption[] {
  cached ??= zonesFrom(browserZones(), Date.now())
  const id = current ? canonicalZone(current) : ''
  if (!id || cached.some((o) => o.id === id)) return cached
  return zonesFrom([...cached.map((o) => o.id), id], Date.now())
}

/** searchZones keeps the zones whose city, region, name, offset or older
 *  name holds every word of the query. */
export function searchZones(all: ZoneOption[], query: string): ZoneOption[] {
  const terms = query.toLowerCase().replace(/_/g, ' ').split(/\s+/).filter(Boolean)
  if (terms.length === 0) return all
  return all.filter((o) => terms.every((t) => o.haystack.includes(t)))
}

/** zoneText is the one line a chosen zone reads as in the closed field. */
export function zoneText(o: ZoneOption): string {
  return [o.offset, o.region ? `${o.city} (${o.region})` : o.city, o.name].filter(Boolean).join(' · ')
}
