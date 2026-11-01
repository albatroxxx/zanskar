import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errorMessage, query } from '../../api/client'
import type { HostKeyStatus, Page, Protocol, Target } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Badge } from '../../components/ui'

/** Protocols that carry a single TCP port and apply to VM targets and ASGs. */
export type PortProtocol = 'ssh' | 'rdp' | 'vnc' | 'winrm'
export const protocols: PortProtocol[] = ['ssh', 'rdp', 'vnc', 'winrm']
/** Protocols a policy may grant: the port protocols, brokered database access (ADR 0017) and applications (ADR 0034). */
export const policyProtocols: Protocol[] = [...protocols, 'database', 'http']

/**
 * useDebounced returns value only after it has stopped changing for delayMs,
 * so a search box fetches once the user pauses rather than on every keystroke.
 */
export function useDebounced<T>(value: T, delayMs = 200): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setSettled(value), delayMs)
    return () => clearTimeout(id)
  }, [value, delayMs])
  return settled
}

/** listPages caps how many pages useList follows: 10,000 rows at 500 a page. */
export const listPages = 20

/**
 * useList fetches a paged collection, every page of it, and exposes reload.
 * It asked for one page of 500 and stopped (until 1.9.0), so past 500 hosts,
 * users or groups the policy editor's lists silently missed some, and where
 * an endpoint caps a page lower than that, sooner. It follows next_cursor up
 * to listPages pages and says when it stopped short (truncated). An answer
 * to a superseded request is dropped, so a quick change of params cannot be
 * overwritten by the slower, older one.
 */
export function useList<T>(path: string, params: Record<string, string | number | boolean | undefined> = {}) {
  const [items, setItems] = useState<T[] | null>(null)
  const [truncated, setTruncated] = useState(false)
  const [err, setErr] = useState('')
  const key = JSON.stringify(params)
  const latest = useRef(0)
  const reload = useCallback(() => {
    const run = ++latest.current
    return fetchAll<T>(path, JSON.parse(key) as Record<string, string>)
      .then((r) => {
        if (run !== latest.current) return
        setItems(r.items)
        setTruncated(r.truncated)
        setErr('')
      })
      .catch((e) => {
        if (run === latest.current) setErr(errorMessage(e))
      })
  }, [path, key])
  useEffect(() => {
    void reload()
  }, [reload])
  return { items, truncated, err, setErr, reload }
}

/** fetchAll reads every page of path, up to listPages of them. */
async function fetchAll<T>(path: string, params: Record<string, string>): Promise<{ items: T[]; truncated: boolean }> {
  const items: T[] = []
  let cursor: string | undefined
  let pages = 0
  do {
    const p = await api.get<Page<T>>(path + query({ limit: 500, ...params, ...(cursor ? { cursor } : {}) }))
    items.push(...(p.items ?? []))
    cursor = p.next_cursor || undefined
    pages++
  } while (cursor && pages < listPages)
  return { items, truncated: Boolean(cursor) }
}

/** usesHostKey says whether an SSH host key means anything for a host: SSH
 *  was found on it, a key is on record, or it was never probed, so nobody
 *  knows yet. A probed host without SSH (a Windows host over RDP) has none,
 *  and "unknown" there read as a fault (the live console, 2026-11-01). */
export function usesHostKey(t: Pick<Target, 'capabilities' | 'host_key_fingerprint' | 'host_key_status' | 'last_probed_at'>): boolean {
  return !t.last_probed_at || t.capabilities.includes('ssh') || !!t.host_key_fingerprint || t.host_key_status !== 'unknown'
}

export function hostKeyBadge(status: HostKeyStatus) {
  const tone = status === 'trusted' ? 'ok' : status === 'pending' ? 'warn' : status === 'changed' ? 'danger' : undefined
  return <Badge tone={tone}>{status}</Badge>
}

/** hostKeyIcon is the table-row form of hostKeyBadge: a state glyph whose
 *  words live on hover and in the aria-label, with the full story on the
 *  target's detail page. */
export function hostKeyIcon(status: HostKeyStatus) {
  switch (status) {
    case 'trusted':
      return <StateIcon state="ok" label="Host key trusted" />
    case 'pending':
      return <StateIcon state="warn" label="Awaiting host key trust" />
    case 'changed':
      return <StateIcon state="danger" label="Host key changed — connections refused" />
    default:
      return <StateIcon state="unknown" label="Never probed" />
  }
}


