import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage, query } from '../../api/client'
import type { HostKeyStatus, Page, Protocol } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Badge } from '../../components/ui'

/** Protocols that carry a single TCP port and apply to VM targets and ASGs. */
export type PortProtocol = 'ssh' | 'rdp' | 'vnc' | 'winrm'
export const protocols: PortProtocol[] = ['ssh', 'rdp', 'vnc', 'winrm']
/** Protocols a policy may grant: the port protocols, brokered database access (ADR 0017) and applications (ADR 0034). */
export const policyProtocols: Protocol[] = [...protocols, 'database', 'http']

/** useList fetches a paged collection and exposes reload. */
export function useList<T>(path: string, params: Record<string, string | number | boolean | undefined> = {}) {
  const [items, setItems] = useState<T[] | null>(null)
  const [err, setErr] = useState('')
  const key = JSON.stringify(params)
  const reload = useCallback(() => {
    return api
      .get<Page<T>>(path + query({ limit: 500, ...(JSON.parse(key) as Record<string, string>) }))
      .then((p) => {
        setItems(p.items ?? [])
        setErr('')
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [path, key])
  useEffect(() => {
    void reload()
  }, [reload])
  return { items, err, setErr, reload }
}

/** parseTags reads "key=value" lines into a map; returns an error string on a bad line. */
export function parseTags(text: string): { tags: Record<string, string>; error?: string } {
  const tags: Record<string, string> = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const i = line.indexOf('=')
    if (i <= 0) return { tags, error: `tag line "${line}" must be key=value` }
    tags[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return { tags }
}

export function formatTags(tags?: Record<string, string>): string {
  return Object.entries(tags ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')
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


