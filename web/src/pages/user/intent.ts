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
// One key per click (zanskar.connect:<time>:<nonce>), not one list: a tab
// taking its record removes its own key and writes nothing else. With one
// list, read, edited and written back, a second click landing while the
// first tab took its record could be written away, and that tab asked
// "Connect?" (the end-to-end suite under load, 2026-11-01). Tabs see each
// other's storage late, so two may take one record; both were clicked for,
// and the spare one lapses.
const intentPrefix = 'zanskar.connect:'
/** The one list 1.12.0 kept; removed on sight. */
const legacyKey = 'zanskar.connect'
/** How long a click's record waits for its tab. */
export const intentTTL = 60_000

interface Click {
  key: string
  href: string
  at: number
}

/** readRecords is the fresh records, oldest first. Expired ones, and any
 *  this code cannot read, go from storage as they are met. */
function readRecords(now: number): Click[] {
  const out: Click[] = []
  try {
    localStorage.removeItem(legacyKey)
    const keys = Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i)).filter((k): k is string => !!k?.startsWith(intentPrefix))
    for (const key of keys) {
      let r: Partial<Click> | null = null
      try {
        r = JSON.parse(localStorage.getItem(key) ?? 'null') as Partial<Click> | null
      } catch {
        r = null
      }
      if (typeof r?.href === 'string' && typeof r.at === 'number' && now - r.at < intentTTL && r.at <= now) out.push({ key, href: r.href, at: r.at })
      else localStorage.removeItem(key)
    }
  } catch {
    // Storage blocked: the new tab shows its Connect button.
    return []
  }
  return out.sort((a, b) => a.at - b.at)
}

/** recordedIntents is the addresses with a fresh record, oldest first. */
export function recordedIntents(now = Date.now()): string[] {
  return readRecords(now).map((r) => r.href)
}

/** recordIntent notes that a session link to href was just clicked; expired
 *  records go on every read, so storage stays short. */
export function recordIntent(href: string, now = Date.now()) {
  readRecords(now)
  const nonce = Array.from(crypto.getRandomValues(new Uint32Array(2)), (n) => n.toString(36)).join('')
  try {
    localStorage.setItem(`${intentPrefix}${now}:${nonce}`, JSON.stringify({ href, at: now }))
  } catch {
    // Storage blocked: the new tab shows its Connect button.
  }
}

/** takeIntent uses up one fresh record for href, the oldest, and says
 *  whether there was one. Two clicks on one link leave two records, for two
 *  tabs. */
export function takeIntent(href: string, now = Date.now()): boolean {
  const mine = readRecords(now).find((r) => r.href === href)
  if (!mine) return false
  try {
    localStorage.removeItem(mine.key)
  } catch {
    // Storage blocked: nothing to use up.
  }
  return true
}
