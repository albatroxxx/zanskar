export function fmtTime(iso?: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
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
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
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
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
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

export function engineName(engine?: string | null, version?: string | null): string {
  if (!engine) return ''
  const name = engineNames[engine] ?? engine
  return version ? `${name} ${version}` : name
}
