import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ApiError } from '../api/client'
import type { Page } from '../api/types'
import { usePaged } from './paged'

/** reads answers each page when the test says, so the test decides the order they land in. */
function reads() {
  const calls: { cursor?: string; answer: (p: Page<string>) => void; fail: (e: unknown) => void }[] = []
  const fetchPage = (cursor?: string) => new Promise<Page<string>>((answer, fail) => void calls.push({ cursor, answer, fail }))
  return { calls, fetchPage }
}

// D14: the sessions, recordings and audit pages each kept a cursor, a busy
// flag and a Load more button. usePaged keeps them for all three, with the
// audit page's generations (B30).
describe('usePaged', () => {
  it('reads the first page, then appends the next one, busy until it lands', async () => {
    const { calls, fetchPage } = reads()
    const { result } = renderHook(() => usePaged(fetchPage))
    expect(result.current.items).toBeNull()

    act(() => void result.current.load())
    act(() => calls[0].answer({ items: ['a', 'b'], next_cursor: 'c1' }))
    await waitFor(() => expect(result.current.items).toEqual(['a', 'b']))
    expect(calls[0].cursor).toBeUndefined()
    expect(result.current.next).toBe('c1')

    act(() => result.current.more())
    expect(calls[1].cursor).toBe('c1')
    expect(result.current.busy).toBe(true)
    act(() => calls[1].answer({ items: ['c'] }))
    await waitFor(() => expect(result.current.busy).toBe(false))
    expect(result.current.items).toEqual(['a', 'b', 'c'])
    expect(result.current.next).toBe('')
  })

  it('drops a page, or its failure, that lands after the list started over', async () => {
    const { calls, fetchPage } = reads()
    const { result } = renderHook(() => usePaged(fetchPage))
    act(() => void result.current.load())
    act(() => calls[0].answer({ items: ['old'], next_cursor: 'c1' }))
    await waitFor(() => expect(result.current.next).toBe('c1'))

    act(() => result.current.more())
    act(() => result.current.restart())
    expect(result.current.items).toBeNull()
    act(() => void result.current.load())
    act(() => calls[2].answer({ items: ['new'] }))
    await waitFor(() => expect(result.current.items).toEqual(['new']))

    act(() => calls[1].answer({ items: ['older'], next_cursor: 'c2' }))
    await waitFor(() => expect(result.current.busy).toBe(false))
    expect(result.current.items).toEqual(['new'])
    expect(result.current.next).toBe('')

    act(() => void result.current.load())
    act(() => void result.current.load())
    act(() => calls[3].fail(new Error('the old read failed')))
    act(() => calls[4].answer({ items: ['newest'] }))
    await waitFor(() => expect(result.current.items).toEqual(['newest']))
    expect(result.current.err).toBe('')
  })

  it('says why a read failed, with the reference a server error carries', async () => {
    const { calls, fetchPage } = reads()
    const { result } = renderHook(() => usePaged(fetchPage))
    act(() => void result.current.load())
    act(() => calls[0].fail(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500')))

    await waitFor(() => expect(result.current.err).toBe('database is locked (reference req-7)'))
    expect(result.current.items).toBeNull()
  })

  it('reads with the fetchPage of the latest render', async () => {
    const seen: string[] = []
    const { result, rerender } = renderHook(({ filter }) => usePaged((cursor) => {
      seen.push(`${filter}:${cursor ?? ''}`)
      return Promise.resolve({ items: [filter], next_cursor: 'c1' })
    }), { initialProps: { filter: 'alice' } })
    const load = result.current.load

    rerender({ filter: 'bob' })
    expect(result.current.load).toBe(load)
    act(() => void result.current.load())
    await waitFor(() => expect(result.current.items).toEqual(['bob']))
    act(() => result.current.more())
    await waitFor(() => expect(result.current.items).toEqual(['bob', 'bob']))

    expect(seen).toEqual(['bob:', 'bob:c1'])
  })
})
