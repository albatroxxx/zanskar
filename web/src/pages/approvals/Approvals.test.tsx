import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { AccessRequest } from '../../api/types'
import { AuthProvider } from '../../auth/AuthContext'
import { ApproverApprovals } from './Approvals'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const ana = { id: 'u9', username: 'ana', display_name: 'Ana', status: 'active', roles: ['user', 'approver'], created_at: '2026-09-01T10:00:00Z' }

const bobs: AccessRequest = {
  id: 'r1', user_id: 'u1', username: 'bob', target_id: 't1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy',
  requested_minutes: 60, status: 'pending', state: 'pending', created_at: '2026-11-16T10:00:00Z', updated_at: '2026-11-16T10:00:00Z',
  named: true, approvers: [{ kind: 'group', id: 'g1', name: 'ops' }, { kind: 'user', id: 'u9', name: 'ana' }],
}
// Ana's own request, in her scope because the grant names her too.
const own: AccessRequest = { ...bobs, id: 'r2', user_id: 'u9', username: 'ana', reason: 'hotfix' }
const active: AccessRequest = { ...bobs, id: 'r3', username: 'carol', status: 'approved', state: 'approved', approved_minutes: 30, expires_at: '2026-11-16T12:00:00Z' }
const past: AccessRequest = { ...bobs, id: 'r4', username: 'dan', status: 'denied', state: 'denied', decision_note: 'not today', decided_at: '2026-11-15T09:00:00Z' }

/** mount signs ana in and answers her scope: the two status lists the queue
 *  reads, and the whole scope the history reads. */
function mount(items = { pending: [bobs, own], approved: [active], all: [bobs, own, active, past] }) {
  const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') return { user: ana, csrf_token: 't', mfa_enrolled: true } as never
    if (path === '/access-requests?scope=mine&status=pending') return { items: items.pending } as never
    if (path === '/access-requests?scope=mine&status=approved') return { items: items.approved } as never
    if (path === '/access-requests?scope=mine') return { items: items.all } as never
    return { items: [] } as never
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
  render(
    <MemoryRouter initialEntries={['/approvals']}>
      <AuthProvider>
        <ApproverApprovals />
      </AuthProvider>
    </MemoryRouter>,
  )
  return { get, post }
}

// The approver's portal (ADR 0049): the requests the grants name them for,
// read in their scope and nobody else's; their own request is theirs to
// see and never to decide; what they decided stays below.
describe('the approver\'s queue', () => {
  it('reads the caller\'s scope, lists what waits, what runs and what was decided', async () => {
    const { get } = mount()
    expect(await screen.findByRole('heading', { name: 'Approvals' })).toBeDefined()
    expect(await screen.findByText('deploy')).toBeDefined()
    expect(get).toHaveBeenCalledWith('/access-requests?scope=mine&status=pending')
    expect(get).toHaveBeenCalledWith('/access-requests?scope=mine&status=approved')
    expect(get).toHaveBeenCalledWith('/access-requests?scope=mine')
    expect(get).not.toHaveBeenCalledWith('/access-requests?status=pending')
    // The approvers column names who decides.
    expect(screen.getByRole('columnheader', { name: 'Approvers' })).toBeDefined()
    expect(screen.getAllByText('ops, ana').length).toBe(2)
    // Active grants carry Revoke; history carries the outcome and the note.
    expect(screen.getByText('carol')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeDefined()
    const history = screen.getByRole('heading', { name: 'History' }).closest('.card') as HTMLElement
    expect(within(history).getByText('dan')).toBeDefined()
    expect(within(history).getByText('denied')).toBeDefined()
    expect(within(history).getByText('not today')).toBeDefined()
  })

  it('offers no decision on the caller\'s own request, and says it is theirs', async () => {
    mount()
    const rows = (await screen.findAllByText('web-1')).map((el) => el.closest('tr') as HTMLElement)
    const bobRow = rows.find((tr) => within(tr).queryByText('bob')) as HTMLElement
    const anaRow = rows.find((tr) => within(tr).queryByText('hotfix')) as HTMLElement
    expect(within(bobRow).getByRole('button', { name: 'Approve…' })).toBeDefined()
    expect(within(bobRow).getByRole('button', { name: 'Deny' })).toBeDefined()
    expect(within(anaRow).queryByRole('button')).toBeNull()
    expect(within(anaRow).getByText('yours')).toBeDefined()
  })

  it('approves and denies through the request\'s routes, and reads again', async () => {
    const { get, post } = mount()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Deny' }))
    expect(post).toHaveBeenCalledWith('/access-requests/r1/deny', {})
    const reads = get.mock.calls.length
    await user.click(screen.getByRole('button', { name: 'Approve…' }))
    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText(/Note/), 'go')
    await user.click(within(dialog).getByRole('button', { name: /Approve for 60 min/ }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/access-requests/r1/approve', { minutes: 60, note: 'go' }))
    await waitFor(() => expect(get.mock.calls.length).toBeGreaterThan(reads))
  })

  it('shows the gateway\'s refusal when a decision is not the caller\'s to make', async () => {
    const { post } = mount()
    post.mockRejectedValueOnce(new ApiError(403, { code: 'own_request', message: 'you cannot decide your own request', request_id: 'r' }, '403'))
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Deny' }))
    expect(await screen.findByText(/you cannot decide your own request/)).toBeDefined()
  })

  it('says when nothing waits and nothing was decided', async () => {
    mount({ pending: [], approved: [], all: [] })
    expect(await screen.findByText('No requests are waiting.')).toBeDefined()
    expect(screen.getByText('No active grants.')).toBeDefined()
    expect(screen.getByText('Nothing decided yet.')).toBeDefined()
  })
})
