// What a session link asks for, where it points, and the record that says
// one was just clicked (ADR 0038). Kept apart from the components in
// connect.tsx, which import it.

import type { Protocol } from '../../api/types'

/** What a session link asks for. Ids only: a credential is typed in the tab
 *  that connects and never goes into an address. */
export interface ConnectIntent {
  /** A machine, a database or an application. */
  target?: string
  /** An autoscaling group: its newest healthy instance, or instance. */
  asg?: string
  instance?: string
  protocol: Protocol
  /** Sign in with the user's own login (ADR 0036): the tab asks for it. */
  own?: boolean
}

const protocols: Protocol[] = ['ssh', 'rdp', 'vnc', 'winrm', 'database', 'http']
const idShape = /^[A-Za-z0-9_-]{1,64}$/

/** connectHref is the address of the page that connects for intent. */
export function connectHref(i: ConnectIntent): string {
  const q = new URLSearchParams()
  if (i.target) q.set('target', i.target)
  if (i.asg) q.set('asg', i.asg)
  if (i.instance) q.set('instance', i.instance)
  q.set('protocol', i.protocol)
  if (i.own) q.set('own', '1')
  return `/connect?${q.toString()}`
}

/** parseIntent reads an intent from the page's query, or null when it names
 *  no target, an unknown protocol, or an id of a shape the gateway never
 *  makes (the ids go into API bodies). */
export function parseIntent(q: URLSearchParams): ConnectIntent | null {
  const protocol = q.get('protocol') as Protocol | null
  if (!protocol || !protocols.includes(protocol)) return null
  const target = q.get('target') ?? undefined
  const asg = q.get('asg') ?? undefined
  const instance = q.get('instance') ?? undefined
  if (![target, asg, instance].every((v) => v === undefined || idShape.test(v))) return null
  if (target ? asg || instance : !asg) return null
  return { target, asg, instance, protocol, own: q.get('own') === '1' || undefined }
}

// The record of links just clicked. A tab opened at /connect connects by
// itself only when a page of ours wrote a record for its address seconds
// before: a link from anywhere else (another site, a bookmark, a pasted
// address) shows a Connect button instead, so nobody's session is started
// for them by a page they happened to open. The record is no secret; it
// proves only that this origin made the link, which another site cannot.
const intentKey = 'zanskar.connect'
/** How long a click's record waits for its tab. */
export const intentTTL = 60_000

interface Click {
  href: string
  at: number
}

function readRecords(now: number): Click[] {
  try {
    const all = JSON.parse(localStorage.getItem(intentKey) ?? '[]') as unknown
    if (!Array.isArray(all)) return []
    return all.filter((r): r is Click => typeof r?.href === 'string' && typeof r?.at === 'number' && now - r.at < intentTTL && r.at <= now)
  } catch {
    return []
  }
}

function writeRecords(records: Click[]) {
  try {
    if (records.length === 0) localStorage.removeItem(intentKey)
    else localStorage.setItem(intentKey, JSON.stringify(records))
  } catch {
    // Storage blocked: the new tab shows its Connect button.
  }
}

/** recordIntent notes that a session link to href was just clicked; expired
 *  records go on every write, so the list stays short. */
export function recordIntent(href: string, now = Date.now()) {
  writeRecords([...readRecords(now), { href, at: now }])
}

/** takeIntent uses up one fresh record for href and says whether there was
 *  one. Two clicks on one link leave two records, for two tabs. */
export function takeIntent(href: string, now = Date.now()): boolean {
  const records = readRecords(now)
  const at = records.findIndex((r) => r.href === href)
  if (at < 0) {
    writeRecords(records)
    return false
  }
  records.splice(at, 1)
  writeRecords(records)
  return true
}
