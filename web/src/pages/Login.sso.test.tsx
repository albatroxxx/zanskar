import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { Login } from './Login'

vi.mock('qrcode', () => ({ default: { toDataURL: async () => 'data:image/png;base64,AA==' } }))

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03 live audit, idea 1: a provider the gateway cannot reach is said
// under its button before anyone presses it and waits.

function signIn(items: { id: string; name: string; type: string; not_answering?: boolean }[]) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
    if (path === '/auth/providers') return { items } as never
    return { text: '' } as never
  })
  render(
    <MemoryRouter>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('a single sign-on provider', () => {
  it('that is not answering says so under its own button, which still works', async () => {
    signIn([
      { id: 'kc', name: 'Keycloak', type: 'oidc', not_answering: true },
      { id: 'ak', name: 'Authentik', type: 'oidc' },
    ])
    const note = await screen.findByText('Keycloak is not answering right now. A password account still works.')
    const button = screen.getByRole('link', { name: 'Continue with Keycloak' })
    expect(button.getAttribute('aria-describedby')).toBe(note.id)
    expect(button.getAttribute('href')).toContain('/api/v1/auth/oidc/kc/start')
    expect(screen.getByRole('link', { name: 'Continue with Authentik' }).getAttribute('aria-describedby')).toBeNull()
    expect(screen.queryByText(/Authentik is not answering/)).toBeNull()
  })

  it('that answers carries no note', async () => {
    signIn([{ id: 'kc', name: 'Keycloak', type: 'oidc' }])
    await screen.findByRole('link', { name: 'Continue with Keycloak' })
    expect(screen.queryByText(/not answering/)).toBeNull()
  })
})
