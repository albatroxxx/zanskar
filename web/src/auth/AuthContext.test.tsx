import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider, useAuth } from './AuthContext'
import { browser, providerSignOut } from './signOut'

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

function SignOut() {
  const { logout, status } = useAuth()
  return <button onClick={() => void logout()}>sign out ({status})</button>
}

// ADR 0035: signing out of a session from a single sign-on provider goes on
// to the provider's own sign-out page, so the next sign-in asks for the
// password again. Only an https URL is followed.
describe('logout', () => {
  const run = async (answer: unknown) => {
    vi.spyOn(api, 'get').mockResolvedValue(me as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue(answer as never)
    const assign = vi.spyOn(browser, 'assign').mockImplementation(() => {})
    render(
      <AuthProvider>
        <SignOut />
      </AuthProvider>,
    )
    const button = await screen.findByText('sign out (full)')
    await act(async () => { button.click() })
    expect(post).toHaveBeenCalledWith('/auth/logout')
    expect(await screen.findByText('sign out (anonymous)')).toBeDefined()
    return assign
  }

  it('goes on to the provider when the gateway names its sign-out page', async () => {
    const to = 'https://kc.example/realms/zanskar/protocol/openid-connect/logout?client_id=zanskar&id_token_hint=x'
    const assign = await run({ status: 'ok', redirect: to })
    expect(assign).toHaveBeenCalledWith(to)
  })

  it('stays here for a local session', async () => {
    const assign = await run({ status: 'ok' })
    expect(assign).not.toHaveBeenCalled()
  })

  it('never follows anything but https', async () => {
    for (const bad of ['javascript:alert(1)', 'http://kc.example/logout', '/login', 'not a url', 42]) {
      expect(providerSignOut(bad)).toBeNull()
    }
    const assign = await run({ status: 'ok', redirect: 'javascript:alert(1)' })
    expect(assign).not.toHaveBeenCalled()
  })
})
