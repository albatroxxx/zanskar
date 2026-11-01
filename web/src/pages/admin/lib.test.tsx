import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { HostKeyStatus, Protocol } from '../../api/types'
import { listPages, useList, usesHostKey } from './lib'

afterEach(() => vi.restoreAllMocks())

// Until 1.9.0 useList asked for one page of 500 and ignored next_cursor:
// past 500 targets the policy editor's lists silently lost some.
describe('usesHostKey', () => {
  const t = { capabilities: [] as Protocol[], host_key_fingerprint: null as string | null, host_key_status: 'unknown' as HostKeyStatus, last_probed_at: '2026-11-01T10:00:00Z' as string | null }
  it('says no for a probed host without SSH and without a key', () => {
    expect(usesHostKey({ ...t, capabilities: ['rdp'] })).toBe(false)
  })
  it('says yes for SSH, a key on record, a key in any state, or a host never probed', () => {
    expect(usesHostKey({ ...t, capabilities: ['ssh'] })).toBe(true)
    expect(usesHostKey({ ...t, host_key_fingerprint: 'SHA256:x' })).toBe(true)
    expect(usesHostKey({ ...t, host_key_status: 'changed' })).toBe(true)
    expect(usesHostKey({ ...t, last_probed_at: null })).toBe(true)
  })
})

describe('useList', () => {
  it('follows next_cursor to the last page', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      const cursor = new URL(path, 'http://x').searchParams.get('cursor')
      if (!cursor) return { items: [{ id: 'a' }, { id: 'b' }], next_cursor: 'c2' } as never
      if (cursor === 'c2') return { items: [{ id: 'c' }], next_cursor: 'c3' } as never
      return { items: [{ id: 'd' }] } as never
    })
    const { result } = renderHook(() => useList<{ id: string }>('/targets', { kind: 'host' }))
    await waitFor(() => expect(result.current.items).not.toBeNull())
    expect(result.current.items!.map((t) => t.id)).toEqual(['a', 'b', 'c', 'd'])
    expect(result.current.truncated).toBe(false)
    expect(get).toHaveBeenCalledTimes(3)
    for (const [path] of get.mock.calls) expect(path).toContain('kind=host')
  })

  it('stops at listPages and says so', async () => {
    let n = 0
    vi.spyOn(api, 'get').mockImplementation(async () => ({ items: [{ id: String(n++) }], next_cursor: 'more' }) as never)
    const { result } = renderHook(() => useList<{ id: string }>('/users'))
    await waitFor(() => expect(result.current.items).not.toBeNull())
    expect(result.current.items).toHaveLength(listPages)
    expect(result.current.truncated).toBe(true)
  })

  it('keeps the newest answer when params change mid-flight', async () => {
    let releaseOld: (v: unknown) => void = () => {}
    vi.spyOn(api, 'get').mockImplementation((path: string) =>
      path.includes('q=old') ? (new Promise((r) => (releaseOld = r)) as never) : (Promise.resolve({ items: [{ id: 'new' }] }) as never),
    )
    const { result, rerender } = renderHook(({ q }) => useList<{ id: string }>('/targets', { q }), { initialProps: { q: 'old' } })
    rerender({ q: 'new' })
    await waitFor(() => expect(result.current.items?.[0]?.id).toBe('new'))
    releaseOld({ items: [{ id: 'old' }] })
    await new Promise((r) => setTimeout(r, 0))
    expect(result.current.items!.map((t) => t.id)).toEqual(['new'])
  })
})
