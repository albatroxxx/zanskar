import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { AuthProvider } from './AuthContext'
import { SessionExpired } from './SessionExpired'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const me = { user: { id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'] }, csrf_token: 't', mfa_enrolled: true }

function LoginProbe() {
  const loc = useLocation()
  return <p>login page, back to {(loc.state as { from?: string } | null)?.from ?? 'nowhere'}</p>
}

/** show mounts the dialog the way App does, on a page with a query string. */
function show(path = '/admin/users?tab=groups') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <SessionExpired />
        <Routes>
          <Route path="/login" element={<LoginProbe />} />
          <Route path="*" element={<p>the page</p>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

/** respond makes fetch answer /auth/me with the signed-in account until signedOut, and every other call with 401. */
function respond() {
  const state = { signedOut: false }
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
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

  it('never shows on the login page, which reports failures itself', async () => {
    respond()
    show('/login')
    await screen.findByText(/login page/)
    await expect(api.get('/users')).rejects.toMatchObject({ status: 401 })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
