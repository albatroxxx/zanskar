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

// 2026-10-30, as AWS Identity Center does: a user's groups are picked as
// the user is made, and a group's members as the group is.
describe('UsersGroups linking', () => {
  const groups = [
    { id: 'g1', name: 'ops', description: '', member_count: 1, created_at: '', updated_at: '' },
    { id: 'g2', name: 'corp-admins', description: '', idp_id: 'idp1', member_count: 3, created_at: '', updated_at: '' },
  ]
  const users = [{ id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'] }, { id: 'u2', username: 'bob', display_name: 'Bob', status: 'active', roles: ['user'] }]
  const serve = () =>
    vi.spyOn(api, 'get').mockImplementation(async (path: string) =>
      (path === '/auth/me' ? me : path.startsWith('/groups') ? { items: groups } : path.startsWith('/users') ? { items: users } : { items: [] }) as never,
    )

  it('adds a user straight into groups, and leaves a provider\'s groups to it', async () => {
    serve()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'u9', username: 'cara' } as never)
    render(
      <AuthProvider>
        <UsersGroups />
      </AuthProvider>,
    )
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Add user' }))
    await user.type(screen.getByLabelText(/Username/), 'cara')
    await user.type(screen.getByLabelText('Display name'), 'Cara')
    const synced = (await screen.findByLabelText('corp-admins')) as HTMLInputElement
    expect(synced.disabled).toBe(true)
    expect(screen.getByText('Members come from the provider')).toBeDefined()
    await user.click(screen.getByLabelText('ops'))
    await user.click(screen.getByRole('button', { name: 'Create' }))
    await vi.waitFor(() => expect(post).toHaveBeenCalled())
    expect(post.mock.calls[0][0]).toBe('/users')
    expect((post.mock.calls[0][1] as { group_ids: string[] }).group_ids).toEqual(['g1'])
  })

  it('adds a group with its members', async () => {
    serve()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'g9', name: 'sre' } as never)
    render(
      <AuthProvider>
        <UsersGroups />
      </AuthProvider>,
    )
    const user = userEvent.setup()
    await user.click(await screen.findByRole('tab', { name: 'Groups' }))
    await user.click(await screen.findByRole('button', { name: 'Add group' }))
    await user.type(screen.getByLabelText('Name'), 'sre')
    await user.click(await screen.findByLabelText('Select all users'))
    await user.click(screen.getByRole('button', { name: 'Create' }))
    await vi.waitFor(() => expect(post).toHaveBeenCalled())
    expect(post.mock.calls[0]).toEqual(['/groups', { name: 'sre', description: '', user_ids: ['u1', 'u2'] }])
  })
})
