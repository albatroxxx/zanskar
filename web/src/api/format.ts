// The zone every time in the console is shown in: the display.time_zone
// setting, from /auth/me (2026-10-30). Unset, the browser's own applies.
let displayZone: string | undefined

/** setDisplayZone sets the console's time zone; an unknown name is ignored. */
export function setDisplayZone(zone?: string | null) {
  displayZone = zone && knownZone(zone) ? zone : undefined
}

/** consoleZone is the zone times are shown in now. */
export function consoleZone(): string {
  return displayZone ?? Intl.DateTimeFormat().resolvedOptions().timeZone
}

function knownZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat(undefined, { timeZone: zone })
    return true
  } catch {
    return false
  }
}

/** zoneOffsetMs is how far zone runs ahead of UTC at instant t, in milliseconds. */
export function zoneOffsetMs(t: number, zone: string): number {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: zone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(new Date(t))
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value)
  const wall = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second'))
  return wall - (t - (((t % 1000) + 1000) % 1000))
}

/** zoneLabel writes a zone's offset at t the way people read it: UTC+05:30. */
export function zoneLabel(t: number, zone: string): string {
  const off = Math.round(zoneOffsetMs(t, zone) / 60000)
  const sign = off < 0 ? '-' : '+'
  const abs = Math.abs(off)
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`
}

/**
 * zonedInputToISO reads a datetime-local value ("2026-10-30T14:30") as a
 * time in the console's zone and returns it in UTC, so a filter typed as
 * 14:30 finds the events shown at 14:30. Twice round: the offset at the
 * guess and at the answer differ across a daylight-saving change.
 */
export function zonedInputToISO(local: string, zone: string = consoleZone()): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(local)
  if (!m) return ''
  const [y, mo, d, h, mi, s] = m.slice(1).map((x) => Number(x ?? 0))
  const wall = Date.UTC(y, mo - 1, d, h, mi, s)
  let t = wall - zoneOffsetMs(wall, zone)
  t = wall - zoneOffsetMs(t, zone)
  return new Date(t).toISOString()
}

export function fmtTime(iso?: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: displayZone })
}

/**
 * fmtPreciseTime adds seconds. Log and audit lines are read to work out the
 * order of events, and minute precision collapses a burst of them into one
 * timestamp (manual QA finding 5).
 */
export function fmtPreciseTime(iso?: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: displayZone })
}

export function fmtDuration(startIso: string, endIso?: string | null): string {
  const start = new Date(startIso).getTime()
  const end = endIso ? new Date(endIso).getTime() : Date.now()
  return fmtSeconds(Math.max(0, Math.floor((end - start) / 1000)))
}

export function fmtSeconds(total: number): string {
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const mm = String(m).padStart(2, '0')
  const ss = String(s).padStart(2, '0')
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  if (n < 1024 ** 4) return `${(n / 1024 ** 3).toFixed(1)} GB`
  return `${(n / 1024 ** 4).toFixed(1)} TB`
}

export function shortId(id?: string | null, n = 8): string {
  return id ? id.slice(0, n) : ''
}

/**
 * engineName is how a database engine is written for people. The drawer used to
 * print the raw identifier while the table beside it printed the proper name
 * (manual QA finding 6), so both read from here.
 */
const engineNames: Record<string, string> = { postgres: 'PostgreSQL', mysql: 'MySQL', mariadb: 'MariaDB' }

/** dbTLS says in words what a database target's TLS mode protects against,
 *  and whether that is the verified default (ADR 0025). A missing mode is
 *  treated as the gateway treats it: verified. */
export function dbTLS(mode?: string | null): { label: string; verified: boolean } {
  switch (mode || 'verify-full') {
    case 'verify-full': return { label: 'Verified', verified: true }
    case 'require': return { label: 'Encrypted, not verified', verified: false }
    case 'prefer': return { label: 'Encrypted if offered, not verified', verified: false }
    case 'disable': return { label: 'Not encrypted', verified: false }
    default: return { label: mode ?? '', verified: false }
  }
}

/** appTLS says how the isolated browser reaches an application's upstream
 *  (ADR 0034): verified TLS against the system roots or the given bundle, or
 *  plain HTTP on a network the administrator trusts. */
export function appTLS(t: { app_upstream?: string; tls_ca?: string }): { label: string; verified: boolean } {
  if (!t.app_upstream?.startsWith('https://')) return { label: 'plain HTTP', verified: false }
  return { label: t.tls_ca ? 'TLS, verified against the CA bundle' : 'TLS, verified against the system roots', verified: true }
}

export function engineName(engine?: string | null, version?: string | null): string {
  if (!engine) return ''
  const name = engineNames[engine] ?? engine
  return version ? `${name} ${version}` : name
}

/** protocolName is how a protocol reads in the console: SSH, RDP and VNC are
 *  acronyms, WinRM keeps its own spelling, and "database" is a word rather
 *  than a shouted code. */
export function protocolName(p: string): string {
  switch (p) {
    case 'winrm': return 'WinRM'
    case 'database': return 'database'
    default: return p.toUpperCase()
  }
}
