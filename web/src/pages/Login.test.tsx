import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { Login } from './Login'

// jsdom has no canvas to draw a QR code with; the enrolment step only needs one to show.
vi.mock('qrcode', () => ({ default: { toDataURL: async () => 'data:image/png;base64,AA==' } }))

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// Landed reports where the router ended up after the sign-in.
function Landed() {
  return <div data-testid="landed">{useLocation().pathname}</div>
}

const wrong = () => new ApiError(401, { code: 'invalid_code', message: 'invalid code' }, '401')
const ended = () => new ApiError(401, { code: 'sign_in_ended', message: 'too many wrong codes; sign in again' }, '401')

async function atCodeStep(verify: () => Promise<never>) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
    if (path === '/auth/providers') return { items: [] } as never
    return { text: '' } as never
  })
  vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
    if (path === '/auth/login') return { status: 'mfa_required', csrf_token: 't' } as never
    return verify()
  })
  render(
    <MemoryRouter>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>,
  )
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText('Username'), 'alice')
  await user.type(screen.getByLabelText('Password'), 'a long enough passphrase{Enter}')
  await screen.findByLabelText('Code')
  return user
}

describe('Login', () => {
  // ADR 0029: with no remembered destination, a sign-in goes to /home, which
  // resolves to the portal the account belongs in — the roles are not known
  // until the sign-in answers, so Login itself cannot pick the portal.
  it('sends a sign-in without a destination to /home', async () => {
    const root = { id: 'u1', username: 'root', display_name: 'Root', roles: ['admin'] }
    let signedIn = false
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') {
        if (signedIn) return { user: root, csrf_token: 't' } as never
        throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
      }
      if (path === '/auth/providers') return { items: [] } as never
      return { text: '' } as never
    })
    vi.spyOn(api, 'post').mockImplementation(async () => {
      signedIn = true
      return { status: 'ok', csrf_token: 't', user: root } as never
    })
    render(
      <MemoryRouter initialEntries={['/login']}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/home" element={<Landed />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Username'), 'root')
    await user.type(screen.getByLabelText('Password'), 'a long enough passphrase{Enter}')
    expect((await screen.findByTestId('landed')).textContent).toBe('/home')
  })

  it('stays on the code step after a wrong code', async () => {
    const user = await atCodeStep(() => Promise.reject(wrong()))
    await user.type(screen.getByLabelText('Code'), '000000{Enter}')
    expect((await screen.findByRole('alert')).textContent).toBe('invalid code')
    expect(screen.getByLabelText('Code')).toBeDefined()
  })

  // #205: the attempt that ends the sign-in goes back to the password step.
  it('goes back to the password step when too many wrong codes end the sign-in', async () => {
    const user = await atCodeStep(() => Promise.reject(ended()))
    await user.type(screen.getByLabelText('Code'), '000000{Enter}')
    expect((await screen.findByRole('alert')).textContent).toBe('Too many wrong codes. Sign in again.')
    expect(screen.queryByLabelText('Code')).toBeNull()
    expect(screen.getByLabelText('Username')).toBeDefined()
  })
})

// L6: the sign-in page showed ?error= inside its own alert, word for word.
describe('Login after a failed single sign-on', () => {
  it('shows the reason in its own words and nothing it was handed', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
      if (path === '/auth/providers') return { items: [] } as never
      return { text: '' } as never
    })
    for (const [query, want] of [
      ['?error=not_provisioned', 'There is no account for you here yet. Ask an administrator to add you.'],
      ['?error=Your+account+is+locked.+Call+%2B1+555+0100', 'Single sign-on did not complete. Try again, or ask an administrator.'],
    ]) {
      window.history.pushState({}, '', '/login' + query)
      render(
        <MemoryRouter>
          <AuthProvider>
            <Login />
          </AuthProvider>
        </MemoryRouter>,
      )
      expect(await screen.findByText(want)).toBeDefined()
      expect(document.body.textContent).not.toMatch(/555 0100|locked/)
      cleanup()
    }
    window.history.pushState({}, '', '/')
  })
})

// B20: the gateway's single sign-on sends a sign-in that still owes a code to
// /login?next=<where the user was going>, and the page read only the router's
// state, so the deep link was lost. A ?next= that is a path on this site is
// where the page goes once signed in; anything else goes home (L7's rule).
describe('Login after signing in', () => {
  it('goes to ?next= when it is a path on this site', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return { user: { id: 'u1', username: 'alice', display_name: 'Alice', roles: ['user'] }, csrf_token: 't', mfa_enrolled: true } as never
      if (path === '/auth/providers') return { items: [] } as never
      return { text: '' } as never
    })
    for (const [next, want] of [
      ['/admin/targets?tab=2', '/admin/targets?tab=2'],
      ['//evil.example/x', '/'],
    ]) {
      render(
        <MemoryRouter initialEntries={['/login?next=' + encodeURIComponent(next)]}>
          <AuthProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="*" element={<Where />} />
            </Routes>
          </AuthProvider>
        </MemoryRouter>,
      )
      expect(await screen.findByText('at ' + want)).toBeDefined()
      cleanup()
    }
  })
})

// Saving the recovery codes went on with window.location.href = from: a new
// page load fed by the ?next= the page was handed, which CodeQL rightly reads
// as a URL taken from the address bar and loaded. It goes on through the
// router now, to the same place.
describe('Login after setting up an authenticator', () => {
  it('goes on to ?next= once the recovery codes are saved', async () => {
    let enrolled = false
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') {
        return (enrolled
          ? { user: { id: 'u1', username: 'alice', display_name: 'Alice', roles: ['user'] }, csrf_token: 't', mfa_enrolled: true }
          : { csrf_token: 't', mfa_enrolled: false, pending: 'enroll' }) as never
      }
      if (path === '/auth/providers') return { items: [] } as never
      return { text: '' } as never
    })
    vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
      if (path === '/auth/mfa/totp/enroll') return { secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/zanskar:alice' } as never
      if (path === '/auth/mfa/totp/confirm') {
        enrolled = true
        return { recovery_codes: ['aaaa-bbbb'] } as never
      }
      throw new Error('no route ' + path)
    })
    render(
      <MemoryRouter initialEntries={['/login?next=' + encodeURIComponent('/admin/targets')]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="*" element={<Where />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    await screen.findByAltText('TOTP enrollment QR code')
    await user.type(screen.getByLabelText('Code from the app'), '123456{Enter}')
    await user.click(await screen.findByRole('button', { name: 'I have saved them' }))

    expect(await screen.findByText('at /admin/targets')).toBeDefined()
  })
})

function Where() {
  const loc = useLocation()
  return <p>at {loc.pathname + loc.search}</p>
}

// 2026-10-30: one full-width button per single sign-on provider, under an
// "or" rule, worded with the provider's name; LDAP signs in through the form
// and gets no button. The button is a link styled as a button (sso-btn),
// which never underlines.
describe('Login with single sign-on providers', () => {
  it('offers a button per OIDC provider', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
      if (path === '/auth/providers') return { items: [{ id: 'kc1', name: 'Keycloak', type: 'oidc' }, { id: 'ad1', name: 'Corp AD', type: 'ldap' }] } as never
      return { text: '' } as never
    })
    render(
      <MemoryRouter>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </MemoryRouter>,
    )
    const link = await screen.findByRole('link', { name: 'Continue with Keycloak' })
    expect(link.getAttribute('href')).toBe('/api/v1/auth/oidc/kc1/start?next=%2Fhome')
    expect(link.className).toBe('btn sso-btn')
    expect(screen.getByRole('separator', { name: 'or' })).toBeDefined()
    expect(screen.queryByRole('link', { name: /Corp AD/ })).toBeNull()
  })
})
