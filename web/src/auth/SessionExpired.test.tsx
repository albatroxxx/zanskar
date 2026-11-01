import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { MemoryRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { AuthProvider, useAuth } from './AuthContext'
import { SessionExpired } from './SessionExpired'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const me = { user: { id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'] }, csrf_token: 't', mfa_enrolled: true }

function LoginProbe() {
  const loc = useLocation()
  const auth = useAuth()
  return (
    <>
      <p>login page, back to {(loc.state as { from?: string } | null)?.from ?? 'nowhere'}</p>
      <p>signed {auth.status}</p>
    </>
  )
}

/** BouncingLogin does what the login page does with a full session: sends it back where it came from. */
function BouncingLogin() {
  const loc = useLocation()
  const auth = useAuth()
  if (auth.status === 'full') return <Navigate to={(loc.state as { from?: string } | null)?.from ?? '/'} replace />
  return <p>login page</p>
}

/** show mounts the dialog the way App does, on a page with a query string. */
function show(path = '/admin/users?tab=groups', login: ReactNode = <LoginProbe />) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <SessionExpired />
        <Routes>
          <Route path="/login" element={login} />
          <Route path="*" element={<p>the page</p>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

/** respond makes fetch answer /auth/me with the signed-in account until signedOut (not at all while hang), and every other call with 401. */
function respond() {
  const state = { signedOut: false, hang: false }
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    if (url.endsWith('/api/v1/auth/me') && state.hang) return new Promise<Response>(() => {})
    if (url.endsWith('/api/v1/auth/me') && !state.signedOut) return new Response(JSON.stringify(me), { status: 200, headers: { 'Content-Type': 'application/json' } })
    return new Response(JSON.stringify({ code: 'unauthenticated', message: 'sign in required' }), { status: 401, statusText: 'Unauthorized' })
  })
  return state
}

describe('SessionExpired', () => {
  it('stays out of the way until a call outside /auth answers 401, then interrupts once', async () => {
    respond()
    show()
    expect(await screen.findByText('the page')).toBeDefined()
    expect(screen.queryByRole('dialog')).toBeNull()
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401, sessionEnded: true })
    expect(await screen.findByRole('dialog', { name: 'Session expired' })).toBeDefined()
    expect(screen.getByText('the page')).toBeDefined() // still visible behind it
    await expect(api.get('/groups')).rejects.toMatchObject({ status: 401 })
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
  })

  it('asks the server again before leaving, then goes to sign in with the way back', async () => {
    const state = respond()
    show()
    await screen.findByText('the page')
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401 })
    const dialog = await screen.findByRole('dialog', { name: 'Session expired' })
    state.signedOut = true
    const fetchSpy = globalThis.fetch as unknown as ReturnType<typeof vi.fn>
    const before = fetchSpy.mock.calls.length
    await userEvent.setup().click(screen.getByRole('button', { name: 'Go to sign in' }))
    await waitFor(() => expect(screen.getByText('login page, back to /admin/users?tab=groups')).toBeDefined())
    expect(fetchSpy.mock.calls.slice(before).some((c) => String(c[0]).endsWith('/api/v1/auth/me'))).toBe(true)
    expect(dialog.isConnected).toBe(false)
  })

  // 2026-11-01, the live console after the computer slept: the check "Go to
  // sign in" waits for never came back, and the dialog stayed on "Taking you
  // to sign in…" until a click outside it asked again.
  it('goes to sign in when the gateway does not answer the check, signed out here', async () => {
    const state = respond()
    show()
    await screen.findByText('the page')
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401 })
    await screen.findByRole('dialog', { name: 'Session expired' })
    state.hang = true
    const fetchSpy = globalThis.fetch as unknown as ReturnType<typeof vi.fn>
    const checks = () => fetchSpy.mock.calls.filter((c) => String(c[0]).endsWith('/api/v1/auth/me')).length
    const before = checks()
    vi.useFakeTimers()
    try {
      fireEvent.click(screen.getByRole('button', { name: 'Go to sign in' }))
      expect(screen.getByRole('button', { name: 'Taking you to sign in…' })).toBeDefined()
      // A click outside while it waits asks nothing more of the gateway.
      fireEvent.mouseDown(document.querySelector('.modal-backdrop') as Element)
      expect(checks()).toBe(before + 1)
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })
      expect(screen.getByText('login page, back to /admin/users?tab=groups')).toBeDefined()
      expect(screen.getByText('signed anonymous')).toBeDefined()
      expect(screen.queryByRole('dialog')).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  // A call refused while the gateway still says the session is good: the
  // login page sends the person back, the next refusal opens the dialog
  // again, and its button was still "Taking you to sign in…", disabled.
  it('opens again with a button that works', async () => {
    respond()
    show('/admin/users?tab=groups', <BouncingLogin />)
    await screen.findByText('the page')
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401 })
    await screen.findByRole('dialog', { name: 'Session expired' })
    await userEvent.setup().click(screen.getByRole('button', { name: 'Go to sign in' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    // The login page sends the person back once the session check answers;
    // until then it shows itself (a slower CI runner caught it there).
    expect(await screen.findByText('the page')).toBeDefined()
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401 })
    await screen.findByRole('dialog', { name: 'Session expired' })
    expect((screen.getByRole('button', { name: 'Go to sign in' }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('never shows on the login page, which reports failures itself', async () => {
    respond()
    show('/login')
    await screen.findByText(/login page/)
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401 })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
