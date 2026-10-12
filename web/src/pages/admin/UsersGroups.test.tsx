import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { AuthProvider } from '../../auth/AuthContext'
import { UsersGroups } from './UsersGroups'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const me = { user: { id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'] }, csrf_token: 't', mfa_enrolled: true }

// B28: the tab bar showed which tab was open only by its styling, so a
// screen reader announced two plain buttons and never which one was open.
describe('UsersGroups tabs', () => {
  it('are a tab list that says which tab is open, and arrows move between them', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => (path === '/auth/me' ? me : { items: [] }) as never)
    render(
      <AuthProvider>
        <UsersGroups />
      </AuthProvider>,
    )

    const tabs = await screen.findByRole('tablist', { name: 'Users and groups' })
    const users = screen.getByRole('tab', { name: 'Users' })
    expect(users.getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('tab', { name: 'Groups' }).getAttribute('aria-selected')).toBe('false')

    users.focus()
    await userEvent.setup().keyboard('{ArrowRight}')

    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Groups' }))
    expect(screen.getByRole('tab', { name: 'Groups', selected: true })).toBeDefined()
    expect(tabs.querySelectorAll('[tabindex="0"]')).toHaveLength(1)
  })
})
