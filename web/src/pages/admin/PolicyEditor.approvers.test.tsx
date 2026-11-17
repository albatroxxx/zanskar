import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { PolicyEditor } from './PolicyEditor'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const groups = [{ id: 'g1', name: 'ops', member_count: 2 }]
const users = [
  { id: 'u1', username: 'ana', display_name: 'Ana', status: 'active', roles: ['user', 'approver'] },
  { id: 'u2', username: 'bob', display_name: 'Bob', status: 'active', roles: ['user'] },
]
const targets = [{ id: 't1', name: 'web-1', os_family: 'linux', status: 'active', capabilities: ['ssh'], tags: {} }]

function mount() {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path.startsWith('/groups')) return { items: groups } as never
    if (path.startsWith('/users')) return { items: users } as never
    if (path.startsWith('/targets')) return { items: targets } as never
    return { items: [] } as never
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'p1' } as never)
  render(
    <MemoryRouter initialEntries={['/admin/policies/new']}>
      <Routes>
        <Route path="/admin/policies/new" element={<PolicyEditor />} />
        <Route path="/admin/policies" element={<p>back at the list</p>} />
      </Routes>
    </MemoryRouter>,
  )
  return post
}

/** grantOf is the one grant of the policy the editor last sent. */
function grantOf(post: ReturnType<typeof vi.spyOn>) {
  const body = post.mock.calls.at(-1)![1] as { grants: Record<string, unknown>[] }
  return body.grants[0]
}

/** A saved policy whose approval grant names a user and a group that have
 *  since been deleted (review R3): the grants JSON keeps their ids. */
const stale = {
  id: 'p1', name: 'prod', description: '', enabled: true, subjects: [{ kind: 'group', id: 'g1' }], created_at: '2026-11-01T10:00:00Z', updated_at: '2026-11-01T10:00:00Z',
  grants: [{ id: 'gr1', kind: 'host', targets: [{ id: 't1', protocols: ['ssh'] }], access: 'approval', sign_in: 'target', require_mfa: true, allow_clipboard: false, allow_file_transfer: false,
    idle_timeout_minutes: 15, max_session_minutes: null, time_windows: [], retention_days: null,
    approvers: [{ kind: 'user', id: 'u1' }, { kind: 'user', id: 'u-gone-1234' }, { kind: 'group', id: 'g-gone-5678' }] }],
}

function mountEdit() {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/access-policies/p1') return stale as never
    if (path.startsWith('/groups')) return { items: groups } as never
    if (path.startsWith('/users')) return { items: users } as never
    if (path.startsWith('/targets')) return { items: targets } as never
    return { items: [] } as never
  })
  const put = vi.spyOn(api, 'put').mockResolvedValue({ id: 'p1' } as never)
  render(
    <MemoryRouter initialEntries={['/admin/policies/p1']}>
      <Routes>
        <Route path="/admin/policies/:id" element={<PolicyEditor />} />
        <Route path="/admin/policies" element={<p>back at the list</p>} />
      </Routes>
    </MemoryRouter>,
  )
  return put
}

/** begin names the policy and gives it an audience (a new policy needs
 *  someone), then hands back the first grant's card. */
async function begin(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText('Name'), 'prod')
  const who = screen.getByRole('heading', { name: 'Who' }).closest('.card') as HTMLElement
  await user.click(within(who).getByLabelText('ops'))
  return screen.getByRole('region', { name: 'Grant 1' })
}

// ADR 0049: an approval grant names who decides, picked from the groups
// and the people who may approve; a standing grant sends none.
describe('the grant editor\'s approvers', () => {
  it('shows the picker for an approval grant alone, offers approvers only, and sends what was picked', async () => {
    const post = mount()
    const user = userEvent.setup()
    const card = await begin(user)
    await user.click(within(card).getByLabelText('web-1'))
    expect(within(card).queryByText('Approvers')).toBeNull()

    await user.click(within(card).getByLabelText('Approval (just-in-time)'))
    expect(within(card).getByText('Approvers')).toBeDefined()
    // ana may approve; bob holds no approver role and is not offered.
    expect(within(card).getByLabelText('ana')).toBeDefined()
    expect(within(card).queryByLabelText('bob')).toBeNull()
    await user.click(within(card).getByLabelText('ops'))
    await user.click(within(card).getByLabelText('ana'))

    await user.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    const g = grantOf(post)
    expect(g.access).toBe('approval')
    expect(g.approvers).toEqual([{ kind: 'group', id: 'g1' }, { kind: 'user', id: 'u1' }])
  })

  it('sends no approvers for a standing grant, even after some were picked', async () => {
    const post = mount()
    const user = userEvent.setup()
    const card = await begin(user)
    await user.click(within(card).getByLabelText('web-1'))
    await user.click(within(card).getByLabelText('Approval (just-in-time)'))
    await user.click(within(card).getByLabelText('ops'))
    await user.click(within(card).getByLabelText('Standing'))
    expect(within(card).queryByText('Approvers')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    const g = grantOf(post)
    expect(g.access).toBe('standing')
    expect('approvers' in g).toBe(false)
  })

  // Review R3: a user or group the grant names that no longer exists would be
  // sent back and refused (422 invalid_approver) with nothing to untick; the
  // editor lists it as a row of its own, marked, so it can be removed.
  it('lists an approver that no longer exists as a not-found row, which can be unticked and saved away', async () => {
    const put = mountEdit()
    const user = userEvent.setup()
    const card = await screen.findByRole('region', { name: 'Grant 1' })
    const gone = within(card).getByLabelText('u-gone-1') as HTMLInputElement
    const goneGroup = within(card).getByLabelText('g-gone-5') as HTMLInputElement
    expect(gone.checked).toBe(true)
    expect(goneGroup.checked).toBe(true)
    expect(within(card).getAllByText('not found').length).toBe(2)
    // ana, who exists, stays a plain ticked row.
    expect((within(card).getByLabelText('ana') as HTMLInputElement).checked).toBe(true)
    await user.click(gone)
    await user.click(goneGroup)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][0]).toBe('/access-policies/p1')
    expect(grantOf(put).approvers).toEqual([{ kind: 'user', id: 'u1' }])
  })

  it('shows the gateway\'s refusal of a named approver beside the approvers', async () => {
    const post = mount()
    post.mockRejectedValue(new ApiError(422, { code: 'not_an_approver', message: 'ana does not hold the approver role', request_id: 'r' }, '422'))
    const user = userEvent.setup()
    const card = await begin(user)
    await user.click(within(card).getByLabelText('web-1'))
    await user.click(within(card).getByLabelText('Approval (just-in-time)'))
    await user.click(within(card).getByLabelText('ana'))
    await user.click(screen.getByRole('button', { name: 'Create' }))
    // Once at the top, as every save error; once by the approvers, where the fix is.
    expect((await screen.findAllByText(/ana does not hold the approver role/)).length).toBe(2)
    expect(within(card).getByText(/ana does not hold the approver role/)).toBeDefined()
  })
})
