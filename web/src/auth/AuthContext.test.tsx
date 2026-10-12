import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider, useAuth } from './AuthContext'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

function Status() {
  return <p>status: {useAuth().status}</p>
}

const me = { user: { id: 'u1', username: 'alice', display_name: 'Alice', roles: ['user'] }, csrf_token: 't', mfa_enrolled: true }

// B22: any failure of /auth/me read as signed out, so during the restart the
// console itself offers, a signed-in user was sent to the login form though
// the cookie was still good. Only a 401 signs out; anything else is the
// gateway not answering, shown as such and asked again.
describe('AuthProvider when the gateway does not answer', () => {
  it('waits and asks again instead of signing out', async () => {
    vi.useFakeTimers()
    const get = vi.spyOn(api, 'get')
      .mockRejectedValueOnce(new ApiError(503, { code: 'restarting', message: 'restarting' }, '503'))
      .mockResolvedValueOnce(me as never)
    render(
      <AuthProvider>
        <Status />
      </AuthProvider>,
    )
    await act(async () => { await vi.advanceTimersByTimeAsync(10) })
    expect(screen.getByText('status: unreachable')).toBeDefined()
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(screen.getByText('status: full')).toBeDefined()
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('signs out on a 401', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401'))
    render(
      <AuthProvider>
        <Status />
      </AuthProvider>,
    )
    expect(await screen.findByText('status: anonymous')).toBeDefined()
  })
})
