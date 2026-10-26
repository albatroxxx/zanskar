import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { ApiError, api } from './api/client'
import { AuthProvider } from './auth/AuthContext'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

/** signedIn answers /auth/me with an account holding roles, and every list with nothing. */
function signedIn(roles: string[] | null) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') {
      if (roles === null) throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required', request_id: 'r' }, '401')
      return { user: { id: 'u1', username: 'pat', display_name: 'Pat', status: 'active', roles }, csrf_token: 't', mfa_enrolled: true } as never
    }
    if (path.startsWith('/admin/system/status')) return { version: '1.5.0', started_at: 'x', uptime_seconds: 1, supervisor: 'systemd', live_sessions: 0, env_file: { state: 'unchanged', checked_at: 'x' }, restart_required: false, draining: false } as never
    // The dashboards' own data is not the point here; they show the failure and the portal still stands.
    if (path.startsWith('/admin/overview') || path.startsWith('/audit/overview')) throw new ApiError(503, { code: 'unavailable', message: 'not now', request_id: 'r' }, '503')
    return { items: [] } as never
  })
}

function open(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('App routes', () => {
  it('sends an anonymous visitor to sign in, remembering where they were going', async () => {
    signedIn(null)
    open('/admin/policies?x=1')
    expect(await screen.findByLabelText('Username')).toBeDefined()
  })

  it('keeps a user out of the admin console and lands them on their targets', async () => {
    signedIn(['user'])
    open('/admin/policies')
    expect(await screen.findByRole('heading', { name: 'Targets' })).toBeDefined()
    expect(screen.queryByText('Access policies')).toBeNull()
  })

  it('keeps a review-only account out of the access portal and lands it on the audit dashboard', async () => {
    signedIn(['auditor'])
    open('/')
    expect(await screen.findByRole('link', { name: 'Events' })).toBeDefined()
    expect(screen.queryByRole('link', { name: 'My sessions' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Policies' })).toBeNull()
  })

  it('moves an administrator who follows an old audit link into the console', async () => {
    signedIn(['admin'])
    open('/audit/events?action=user.login')
    expect(await screen.findByRole('heading', { name: 'Audit events' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'Policies' })).toBeDefined()
    expect(screen.queryByRole('link', { name: 'My sessions' })).toBeNull()
  })

  it('resolves the home and unknown paths to the account\'s own portal', async () => {
    signedIn(['admin'])
    const { unmount } = open('/no/such/page')
    expect(await screen.findByRole('link', { name: 'Credentials' })).toBeDefined()
    unmount()
    signedIn(['user'])
    open('/home')
    expect(await screen.findByRole('heading', { name: 'Targets' })).toBeDefined()
  })

  it('tells an account with no role that no portal opens for it, and offers sign-out', async () => {
    signedIn([])
    open('/')
    expect(await screen.findByText(/This account has no role that opens a portal/)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeDefined()
  })
})
