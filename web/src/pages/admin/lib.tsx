import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage, query } from '../../api/client'
import type { HostKeyStatus, Page, Protocol } from '../../api/types'
import { Badge } from '../../components/ui'

export const protocols: Protocol[] = ['ssh', 'rdp', 'vnc', 'winrm']

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

/** Wire shape of a probe as the Go handler returns it (differs from the draft in types.ts). */
export interface PortResult { reachable: boolean; latency_ms: number; error?: string }
export interface ProbeWire {
  address: string
  resolved_ip: string
  ports: Partial<Record<Protocol, PortResult>>
  capabilities: Protocol[]
  ssh_host_key?: { fingerprint: string; type: string; banner: string }
  tls?: { fingerprint: string; subject: string; source: string }
  vnc_version?: string
  probed_at: string
}

