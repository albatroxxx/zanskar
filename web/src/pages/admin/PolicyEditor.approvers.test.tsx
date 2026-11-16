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
