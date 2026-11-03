import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { badgesChanged, shareBadgeCount } from './badges'
import { BADGE_FRESH_MS, Shell } from './Shell'

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

// 2026-10-30 walkthrough: the Approvals badge kept a decided request's count
// until a reload. A badge reads again when the page says its count changed,
// and on a move to another page once its count is not fresh, not only on its
// minute. 2026-11-03 live audit, Q12: it read on every page change, and on
// Approvals a third time beside the page's own two reads; a count under
// BADGE_FRESH_MS old is kept, and the page it counts for hands it over.
describe('a nav badge', () => {
  function mount(load: () => Promise<number>, shared = false) {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return { user: alice, csrf_token: 't', mfa_enrolled: true } as never
      return { items: [] } as never
    })
    render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <Shell
            portal="user"
            items={[
              { to: '/', label: 'Targets', end: true },
              { to: '/sessions', label: 'Sessions' },
              { to: '/approvals', label: 'Approvals', badge: load, badgeShared: shared },
            ]}
          />
        </AuthProvider>
      </MemoryRouter>,
    )
  }

  it('reads again on badgesChanged, and on navigation once the count is stale, and hides at zero', async () => {
    let pending = 2
    const load = vi.fn(async () => pending)
    mount(load)
    expect(await screen.findByLabelText('2 pending')).toBeDefined()

    pending = 1
    act(() => badgesChanged())
    expect(await screen.findByLabelText('1 pending')).toBeDefined()

    // Fresh: a page change reads nothing.
    pending = 0
    const user = userEvent.setup()
    const calls = load.mock.calls.length
    await user.click(screen.getByRole('link', { name: /Sessions/ }))
    await new Promise((r) => setTimeout(r, 50))
    expect(load.mock.calls.length).toBe(calls)
    expect(screen.getByLabelText('1 pending')).toBeDefined()

    // Stale: the next page change reads it.
    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + BADGE_FRESH_MS + 1000)
    await user.click(screen.getByRole('link', { name: /Targets/ }))
    await waitFor(() => expect(load.mock.calls.length).toBeGreaterThan(calls))
    await waitFor(() => expect(screen.queryByLabelText(/pending$/)).toBeNull())
  })

  it('takes the count its page shares, and does not read it on that page', async () => {
    const load = vi.fn(async () => 4)
    mount(load, true)
    expect(await screen.findByLabelText('4 pending')).toBeDefined()
    const calls = load.mock.calls.length
    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + BADGE_FRESH_MS + 1000)
    await userEvent.setup().click(screen.getByRole('link', { name: /Approvals/ }))
    act(() => shareBadgeCount('/approvals', 3))
    expect(await screen.findByLabelText('3 pending')).toBeDefined()
    await new Promise((r) => setTimeout(r, 50))
    expect(load.mock.calls.length).toBe(calls)
    // Another page's count is not this badge's.
    act(() => shareBadgeCount('/elsewhere', 9))
    expect(screen.getByLabelText('3 pending')).toBeDefined()
  })
})
