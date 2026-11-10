import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Policy } from '../../api/types'
import { AuthProvider } from '../../auth/AuthContext'
import { newGrant, standingNoMFA } from './policyModel'
import { Policies } from './Policies'
import { UsersGroups } from './UsersGroups'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-04, live walkthrough of 1.18.3: the security posture tiles opened
// the whole list. Each now opens the set it counted, says so in a chip, and
// the chip drops the filter.

const me = { user: { id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'] }, csrf_token: 't', mfa_enrolled: true }
const users = [
  { id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'], created_at: '', updated_at: '' },
  { id: 'u2', username: 'bob', display_name: 'Bob', status: 'active', roles: ['user'], created_at: '', updated_at: '' },
]

describe('the users list opened from a posture tile', () => {
  it('asks the server for that set, names the filter, and drops it from the chip', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return me as never
      if (path.startsWith('/users') && path.includes('posture=not_enrolled')) return { items: [users[1]] } as never
      if (path.startsWith('/users')) return { items: users } as never
      return { items: [] } as never
    })
    render(
      <MemoryRouter initialEntries={['/admin/users?posture=not_enrolled']}>
        <AuthProvider>
          <UsersGroups />
        </AuthProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByText('bob')).toBeDefined()
    expect(screen.queryByText('alice')).toBeNull()
    expect(get.mock.calls.some(([p]) => String(p).includes('posture=not_enrolled'))).toBe(true)
    const chip = screen.getByRole('button', { name: 'No authenticator yet: remove filter' })

    await userEvent.setup().click(chip)
    expect(await screen.findByText('alice')).toBeDefined()
    expect(screen.queryByRole('button', { name: /remove filter/ })).toBeNull()
  })

  it('ignores a posture it does not know, and shows everyone', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => (path === '/auth/me' ? me : { items: users }) as never)
    render(
      <MemoryRouter initialEntries={['/admin/users?posture=everyone']}>
        <AuthProvider>
          <UsersGroups />
        </AuthProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByText('alice')).toBeDefined()
    expect(screen.queryByRole('group', { name: 'Filters' })).toBeNull()
  })

  it('says nobody matches, not that there are no users', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => (path === '/auth/me' ? me : { items: [] }) as never)
    render(
      <MemoryRouter initialEntries={['/admin/users?posture=dormant']}>
        <AuthProvider>
          <UsersGroups />
        </AuthProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByText('No users match.')).toBeDefined()
  })
})

describe('searching the users list', () => {
  it('asks the server for a word and shows its matches in the order it ranks them', async () => {
    const found = [
      { ...users[1], id: 'u3', username: 'zanskar', display_name: 'Exact' },
      { ...users[1], id: 'u4', username: 'zanskar-keykloak', display_name: 'Zanskar Man' },
    ]
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return me as never
      if (path.startsWith('/users') && path.includes('q=zan')) return { items: found } as never
      if (path.startsWith('/users')) return { items: users } as never
      return { items: [] } as never
    })
    render(
      <MemoryRouter initialEntries={['/admin/users']}>
        <AuthProvider>
          <UsersGroups />
        </AuthProvider>
      </MemoryRouter>,
    )
    expect(await screen.findByText('bob')).toBeDefined()
    await userEvent.setup().type(screen.getByRole('searchbox', { name: 'Search users' }), 'zan')
    expect(await screen.findByText('zanskar-keykloak')).toBeDefined()
    expect(screen.queryByText('bob')).toBeNull()
    const rows = screen.getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('cell')[0].textContent)
    expect(rows).toEqual(['zanskar', 'zanskar-keykloak'])
    expect(get.mock.calls.some(([p]) => String(p).includes('q=zan'))).toBe(true)
  })

  it('says nobody matches a word nobody has', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return me as never
      return { items: path.includes('q=') ? [] : users } as never
    })
    render(
      <MemoryRouter initialEntries={['/admin/users']}>
        <AuthProvider>
          <UsersGroups />
        </AuthProvider>
      </MemoryRouter>,
    )
    await screen.findByText('bob')
    await userEvent.setup().type(screen.getByRole('searchbox', { name: 'Search users' }), 'zzz')
    expect(await screen.findByText('No users match.')).toBeDefined()
  })
})

const policy = (id: string, name: string, over: Partial<Policy> & { mfa?: boolean; access?: 'standing' | 'approval' }): Policy => ({
  id, name, description: '', enabled: true, review_state: 'never_reviewed', subjects: [{ kind: 'user', id: 'u1' }], created_at: '', updated_at: '',
  grants: [{ ...newGrant('host'), id: id + 'g', targets: [{ id: 't1', protocols: ['ssh'] }], access: over.access ?? 'standing', require_mfa: over.mfa ?? true }],
  ...over,
})

describe('standingNoMFA', () => {
  it('is what the dashboard tile counts: enabled, and a grant that is not approval-gated and asks for no authenticator', () => {
    expect(standingNoMFA(policy('a', 'a', { mfa: false }))).toBe(true)
    expect(standingNoMFA(policy('b', 'b', { mfa: true }))).toBe(false)
    expect(standingNoMFA(policy('c', 'c', { mfa: false, access: 'approval' }))).toBe(false)
    expect(standingNoMFA(policy('d', 'd', { mfa: false, enabled: false }))).toBe(false)
  })
})

describe('the policy list opened from the standing-access tile', () => {
  it('lists only those policies, names the filter, and drops it from the chip', async () => {
    const all = [policy('a', 'loose', { mfa: false }), policy('b', 'strict', { mfa: true }), policy('d', 'off', { mfa: false, enabled: false })]
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.startsWith('/access-policies') ? all : [] }) as never)
    render(
      <MemoryRouter initialEntries={['/admin/policies?show=standing_no_mfa']}>
        <Policies />
      </MemoryRouter>,
    )
    const table = await screen.findByRole('table')
    await waitFor(() => expect(within(table).getByText('loose')).toBeDefined())
    expect(within(table).queryByText('strict')).toBeNull()
    expect(within(table).queryByText('off')).toBeNull()

    await userEvent.setup().click(screen.getByRole('button', { name: 'Standing access without MFA: remove filter' }))
    expect(await within(await screen.findByRole('table')).findByText('strict')).toBeDefined()
  })
})
