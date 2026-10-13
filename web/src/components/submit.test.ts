import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ApiError } from '../api/client'
import { useSubmit } from './submit'

// D14: about a dozen forms and dialogs each kept a busy flag and an error,
// and sent with the same try, catch and finally. useSubmit is that code.
describe('useSubmit', () => {
  it('is busy while the request runs, and clears the last error as it starts', async () => {
    let done: () => void = () => {}
    const { result } = renderHook(() => useSubmit())
    act(() => result.current.setErr('name is required'))

    act(() => void result.current.submit(() => new Promise<void>((resolve) => { done = resolve })))
    expect(result.current.busy).toBe(true)
    expect(result.current.err).toBe('')

    act(() => done())
    await waitFor(() => expect(result.current.busy).toBe(false))
    expect(result.current.err).toBe('')
  })

  it('shows a failure in words, a server error with its reference', async () => {
    const { result } = renderHook(() => useSubmit())
    await act(() => result.current.submit(() => Promise.reject(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500'))))

    expect(result.current.err).toBe('database is locked (reference req-7)')
    expect(result.current.busy).toBe(false)
  })

  it('leaves an expired session to the session dialog', async () => {
    const expired = new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
    expired.sessionEnded = true
    const { result } = renderHook(() => useSubmit())
    await act(() => result.current.submit(() => Promise.reject(expired)))

    expect(result.current.err).toBe('')
    expect(result.current.busy).toBe(false)
  })

  it('keeps an error the request sets itself, such as a field it refuses', async () => {
    const { result } = renderHook(() => useSubmit())
    await act(() => result.current.submit(async () => result.current.setErr('certificate lifetime must be 60-3600 seconds')))

    expect(result.current.err).toBe('certificate lifetime must be 60-3600 seconds')
    expect(result.current.busy).toBe(false)
  })
})
