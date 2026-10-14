import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { Shell } from './Shell'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const alice = {
  id: 'u1',
  username: 'alice',
  display_name: 'Alice Verma',
  email: 'alice@example.internal',
  status: 'active',
  roles: ['user'],
  created_at: '2026-09-01T10:00:00Z',
  last_login_at: '2026-10-15T07:30:00Z',
}

// The sidebar shows only the username — the one always-unique line — and the
// account behind it opens on click: what Zanskar knows now, and where an
// identity provider's fields land once one is connected.
describe('the sidebar account', () => {
  it('shows the username alone, and the account details on click', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return { user: alice, csrf_token: 't', mfa_enrolled: true } as never
      return { items: [] } as never
    })
    render(
      <MemoryRouter>
        <AuthProvider>
          <Shell portal="user" items={[]} />
        </AuthProvider>
      </MemoryRouter>,
    )

    const open = await screen.findByRole('button', { name: 'alice' })
    expect(screen.queryByText('Alice Verma')).toBeNull()

    await userEvent.setup().click(open)

    expect(await screen.findByRole('dialog')).toBeDefined()
    expect(screen.getByText('Alice Verma')).toBeDefined()
    expect(screen.getByText('alice@example.internal')).toBeDefined()
    expect(screen.getByText('enrolled')).toBeDefined()
  })
})
