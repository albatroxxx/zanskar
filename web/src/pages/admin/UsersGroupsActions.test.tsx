import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { User } from '../../api/types'
import { AuthProvider } from '../../auth/AuthContext'
import { UsersGroups } from './UsersGroups'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const alice = { id: 'u1', username: 'alice', display_name: 'Alice', status: 'active', roles: ['admin'], created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' } as User
const bob = { id: 'u2', username: 'bob', display_name: 'Bob', email: 'bob@example.com', status: 'active', roles: ['user'], last_login_at: '2026-10-20T10:00:00Z', must_change_password: true, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' } as User
const carol = { id: 'u3', username: 'carol', display_name: 'Carol', status: 'disabled', roles: ['auditor'], created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' } as User
const me = { user: alice, csrf_token: 't', mfa_enrolled: true }

function serve(users: User[] = [alice, bob, carol], groups: unknown[] = [], members: { user_id: string }[] = []) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') return me as never
    if (path.startsWith('/users')) return { items: users } as never
    if (/^\/groups\/[^/]+\/members/.test(path)) return { items: members } as never
    if (path.startsWith('/groups')) return { items: groups } as never
    return { items: [] } as never
  })
}

async function show() {
  render(
    <AuthProvider>
      <UsersGroups />
    </AuthProvider>,
  )
  await screen.findByText('alice')
  return userEvent.setup()
}

/** act picks an entry from a user's actions menu. */
async function act(user: ReturnType<typeof userEvent.setup>, username: string, action: string) {
  await user.selectOptions(screen.getByLabelText(`actions for ${username}`), action)
}

describe('Users', () => {
  // 2026-10-31: the list did not say which people come from an identity
  // provider and which were made in Zanskar.
  it('says where each account comes from', async () => {
    const fromKeycloak = { ...bob, idp_id: 'p1', provider_sign_in: true } as User
    const waiting = { ...carol, provider_sign_in: true } as User
    const get = serve([alice, fromKeycloak, waiting])
    const base = get.getMockImplementation() as (path: string) => Promise<unknown>
    get.mockImplementation(async (path: string) => {
      if (path.startsWith('/identity-providers')) return { items: [{ id: 'p1', name: 'Keycloak', type: 'oidc' }] } as never
      return base(path)
    })
    await show()
    const source = (username: string) => {
      const cell = within(screen.getByText(username).closest('tr') as HTMLElement).getAllByRole('cell')[2]
      return { text: cell.textContent, title: cell.querySelector('.badge')?.getAttribute('title'), idp: !!cell.querySelector('.source-idp') }
    }
    await waitFor(() => expect(source('bob').text).toBe('Keycloak'))
    expect(source('bob')).toEqual({ text: 'Keycloak', title: 'Signs in through Keycloak (OIDC)', idp: true })
    expect(source('carol')).toMatchObject({ text: 'Single sign-on', idp: true })
    expect(source('alice')).toMatchObject({ text: 'Zanskar', idp: false })
    expect(screen.getByRole('columnheader', { name: 'Source' })).toBeDefined()
  })

  // 2026-10-31, the live 1.9.0 report: a person deleted from Keycloak, the
  // sync disabled their account, and the console let it be enabled again.
  it('keeps Enable away from an account its provider took away, while the provider decides', async () => {
    const gone = { ...carol, idp_id: 'p1', directory_removed_at: '2026-10-31T09:00:00Z' } as User
    const byHand = { ...bob, status: 'disabled', idp_id: 'p1' } as User
    const pushedOff = { ...carol, id: 'u4', username: 'dora', idp_id: 'p2', directory_removed_at: '2026-10-31T09:00:00Z' } as User
    const get = serve([alice, gone, byHand, pushedOff])
    const base = get.getMockImplementation() as (path: string) => Promise<unknown>
    get.mockImplementation(async (path: string) => {
      if (path.startsWith('/identity-providers'))
        return {
          items: [
            { id: 'p1', name: 'Keycloak', type: 'oidc', enabled: true, config: { sync_users: true } },
            { id: 'p2', name: 'Old IdP', type: 'oidc', enabled: false, config: { scim: true } },
          ],
        } as never
      return base(path)
    })
    await show()
    const enable = (username: string) => within(screen.getByLabelText(`actions for ${username}`)).getByRole('option', { name: 'Enable' }) as HTMLOptionElement
    await waitFor(() => expect(enable('carol').disabled).toBe(true))
    expect(enable('carol').title).toBe('Keycloak no longer has this person; the account is enabled again when it does')
    expect(within(screen.getByText('carol').closest('tr') as HTMLElement).getByRole('button', { name: 'Disabled: Keycloak no longer has this person' })).toBeDefined()
    // Disabled by an administrator: theirs to enable.
    expect(enable('bob').disabled).toBe(false)
    // A provider that no longer decides (here disabled) lets go of its people.
    expect(enable('dora').disabled).toBe(false)
  })

  it('shows each account, marks the signed-in one, and keeps disable and delete away from it', async () => {
    serve()
    await show()
    // The marker comes from the sign-in lookup, the row from the users
    // list; the two answer in either order, so wait for the marker too.
    await screen.findByText('(you)')
    const mine = screen.getByText('alice').closest('tr')!
    expect(within(mine).getByText('(you)')).toBeDefined()
    expect(within(mine).getByText('admin')).toBeDefined()
    expect(within(mine).getByRole('button', { name: 'Active' })).toBeDefined()
    const options = (name: string) => Array.from((screen.getByLabelText(`actions for ${name}`) as HTMLSelectElement).options).map((o) => o.textContent)
    expect(options('alice')).toEqual(['Actions…', 'Edit roles', 'Reset password', 'Revoke sessions', 'Reset authenticator'])
    expect(options('bob')).toEqual(['Actions…', 'Edit roles', 'Reset password', 'Revoke sessions', 'Reset authenticator', 'Disable', 'Delete'])
    expect(options('carol')).toContain('Enable')

    const bobs = screen.getByText('bob').closest('tr')!
    expect(within(bobs).getByText('bob@example.com')).toBeDefined()
    expect(within(bobs).getByText('password change due')).toBeDefined()
    expect(within(bobs).queryByText('never')).toBeNull()
    const carols = screen.getByText('carol').closest('tr')!
    expect(within(carols).getByRole('button', { name: 'Disabled' })).toBeDefined()
    expect(within(carols).getByText('never')).toBeDefined()
  })

  it('creates an account with a generated one-time password and shows it exactly once', async () => {
    serve()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ...bob, id: 'u9', username: 'dave', initial_password: 'rk2-shown-once-7q' } as never)
    const user = await show()
    await user.click(screen.getByRole('button', { name: 'Add user' }))
    const form = screen.getByRole('dialog', { name: 'Add user' })
    await user.type(within(form).getByLabelText('Username'), ' dave ')
    await user.type(within(form).getByLabelText('Display name'), 'Dave')
    await user.click(within(form).getByLabelText('auditor'))
    expect((within(form).getByLabelText('Initial password') as HTMLInputElement).type).toBe('password')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/users', { username: 'dave', display_name: 'Dave', email: '', roles: ['user', 'auditor'] }))
    const once = await screen.findByRole('dialog', { name: 'One-time password for dave' })
    expect(within(once).getByText('rk2-shown-once-7q')).toBeDefined()
    await user.click(within(once).getByRole('button', { name: 'Done' }))
    expect(screen.queryByText('rk2-shown-once-7q')).toBeNull()
  })

  it('creates an identity-provider account with no password at all', async () => {
    serve()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ...bob, id: 'u9', username: 'erin' } as never)
    const user = await show()
    await user.click(screen.getByRole('button', { name: 'Add user' }))
    const form = screen.getByRole('dialog', { name: 'Add user' })
    await user.type(within(form).getByLabelText('Username'), 'erin')
    await user.type(within(form).getByLabelText('Display name'), 'Erin')
    await user.click(within(form).getByLabelText(/Signs in through an identity provider/))
    expect(within(form).queryByLabelText('Initial password')).toBeNull()
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/users', { username: 'erin', display_name: 'Erin', email: '', roles: ['user'], password_less: true }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('changes roles, resets a password by generating or by setting one, and shows the server\'s refusal', async () => {
    serve()
    const put = vi.spyOn(api, 'put')
      .mockResolvedValueOnce({} as never)
      .mockResolvedValueOnce({ initial_password: 'gen-9-once' } as never)
      .mockRejectedValueOnce(new ApiError(422, { code: 'weak_password', message: 'password must be at least 12 characters', request_id: 'r' }, '422'))
    const user = await show()

    await act(user, 'bob', 'roles')
    const roles = screen.getByRole('dialog', { name: 'Roles for bob' })
    await user.click(within(roles).getByLabelText('admin'))
    await user.click(within(roles).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/users/u2/roles', { roles: ['user', 'admin'] }))

    await act(user, 'bob', 'password')
    const pw = screen.getByRole('dialog', { name: 'Reset password for bob' })
    expect(within(pw).queryByLabelText('New password')).toBeNull()
    await user.click(within(pw).getByRole('button', { name: 'Generate' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/users/u2/password', { generate: true }))
    const once = await screen.findByRole('dialog', { name: 'One-time password for bob' })
    await user.click(within(once).getByRole('button', { name: 'Done' }))

    await act(user, 'bob', 'password')
    const pw2 = screen.getByRole('dialog', { name: 'Reset password for bob' })
    await user.click(within(pw2).getByLabelText(/Generate a one-time password/))
    await user.type(within(pw2).getByLabelText('New password'), 'short but twelve')
    await user.click(within(pw2).getByRole('button', { name: 'Set password' }))
    expect(await within(pw2).findByText('password must be at least 12 characters')).toBeDefined()
    expect(put).toHaveBeenLastCalledWith('/users/u2/password', { password: 'short but twelve' })
  })

  it('revokes sessions, resets the authenticator, disables and deletes, each after a confirmation that says what follows', async () => {
    serve()
    const del = vi.spyOn(api, 'del').mockImplementation(async (path: string) => (path.endsWith('/sessions') ? { sessions_revoked: 3 } : {}) as never)
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    const user = await show()

    await act(user, 'bob', 'sessions')
    let dialog = screen.getByRole('dialog', { name: 'Sign bob out everywhere?' })
    expect(within(dialog).getByText(/every sign-in and live session/)).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Revoke sessions' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/users/u2/sessions'))
    expect(await screen.findByText('Revoked 3 session(s) for bob.')).toBeDefined()

    await act(user, 'bob', 'mfa')
    dialog = screen.getByRole('dialog', { name: "Reset bob's authenticator?" })
    await user.click(within(dialog).getByRole('button', { name: 'Reset authenticator' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/users/u2/mfa'))
    expect(await screen.findByText('Authenticator reset for bob.')).toBeDefined()

    await act(user, 'bob', 'status')
    dialog = screen.getByRole('dialog', { name: 'Disable bob?' })
    expect(within(dialog).getByText(/cannot sign in until re-enabled/)).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/users/u2', { display_name: 'Bob', email: 'bob@example.com', status: 'disabled' }))

    await act(user, 'carol', 'status')
    dialog = screen.getByRole('dialog', { name: 'Enable carol?' })
    await user.click(within(dialog).getByRole('button', { name: 'Enable' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/users/u3', { display_name: 'Carol', email: '', status: 'active' }))

    await act(user, 'bob', 'delete')
    dialog = screen.getByRole('dialog', { name: 'Delete bob?' })
    expect(within(dialog).getByText(/An account with session history cannot be deleted/)).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/users/u2'))
  })

  it('keeps a refused delete in the dialog and names it on the page', async () => {
    serve()
    vi.spyOn(api, 'del').mockRejectedValue(new ApiError(409, { code: 'has_history', message: 'bob has opened sessions; disable the account instead', request_id: 'r' }, '409'))
    const user = await show()
    await act(user, 'bob', 'delete')
    const dialog = screen.getByRole('dialog', { name: 'Delete bob?' })
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    expect(await within(dialog).findByText('bob has opened sessions; disable the account instead')).toBeDefined()
    expect(screen.getByRole('dialog', { name: 'Delete bob?' })).toBeDefined()
  })
})

describe('Groups', () => {
  it('says which groups an identity provider fills', async () => {
    const get = serve([alice], [{ id: 'g1', name: 'ops', description: '', member_count: 2 }, { id: 'g2', name: 'kc-admins', description: '', member_count: 3, idp_id: 'p1' }])
    const base = get.getMockImplementation() as (path: string) => Promise<unknown>
    get.mockImplementation(async (path: string) => {
      if (path.startsWith('/identity-providers')) return { items: [{ id: 'p1', name: 'Keycloak', type: 'oidc' }] } as never
      return base(path)
    })
    const user = await show()
    await user.click(screen.getByRole('tab', { name: 'Groups' }))
    const synced = (await screen.findByText('kc-admins')).closest('tr') as HTMLElement
    await waitFor(() => expect(within(synced).getByText('Keycloak').getAttribute('title')).toBe('Members come from Keycloak (OIDC)'))
    expect(within(screen.getByText('ops').closest('tr') as HTMLElement).getByText('Zanskar')).toBeDefined()
  })

  it('lists groups with member counts, adds one, edits members, and deletes with the warning about policies', async () => {
    serve([alice, bob, carol], [{ id: 'g1', name: 'ops', description: 'Operators', member_count: 2 }], [{ user_id: 'u1' }, { user_id: 'u2' }])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue({} as never)
    const user = await show()
    await user.click(screen.getByRole('tab', { name: 'Groups' }))
    const row = (await screen.findByText('ops')).closest('tr')!
    expect(within(row).getByText('Operators')).toBeDefined()
    expect(within(row).getByText('2')).toBeDefined()

    await user.click(screen.getByRole('button', { name: 'Add group' }))
    const form = screen.getByRole('dialog', { name: 'Add group' })
    await user.type(within(form).getByLabelText('Name'), ' dba ')
    await user.type(within(form).getByLabelText('Description'), 'Database admins')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/groups', { name: 'dba', description: 'Database admins' }))

    await user.click(within(row).getByRole('button', { name: 'Members' }))
    const members = screen.getByRole('dialog', { name: 'Members of ops' })
    const check = (name: string) => within(members).getByRole('checkbox', { name: new RegExp(name) }) as HTMLInputElement
    await waitFor(() => expect(check('Alice').checked).toBe(true))
    expect(check('Bob').checked).toBe(true)
    expect(check('Carol').checked).toBe(false)
    await user.click(check('Bob'))
    await user.click(check('Carol'))
    await user.click(within(members).getByRole('button', { name: 'Save members' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/groups/g1/members', { user_ids: ['u1', 'u3'] }))

    await user.click(within(row).getByRole('button', { name: 'Delete' }))
    const confirm = screen.getByRole('dialog', { name: 'Delete group ops?' })
    expect(within(confirm).getByText(/Its policies are deleted/)).toBeDefined()
    await user.click(within(confirm).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/groups/g1'))
  })

  it('says why a group matters when there is none', async () => {
    serve([alice], [])
    const user = await show()
    await user.click(screen.getByRole('tab', { name: 'Groups' }))
    expect(await screen.findByText('No groups. Policies attach to groups, so create one first.')).toBeDefined()
  })
})
