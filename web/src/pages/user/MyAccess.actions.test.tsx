import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AccessRequest } from '../../api/types'
import { MyAccess } from './MyAccess'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const soon = new Date(Date.now() + 30 * 60_000).toISOString()
const pending: AccessRequest = { id: 'r1', user_id: 'u1', target_id: 't1', target_name: 'db-1', protocol: 'ssh', reason: 'incident 42', status: 'pending', state: 'pending', requested_minutes: 60, created_at: '2026-11-16T08:00:00Z', updated_at: '2026-11-16T08:00:00Z' }
const active: AccessRequest = { ...pending, id: 'r2', status: 'approved', state: 'approved', approved_minutes: 30, expires_at: soon }
const cancelled: AccessRequest = { ...pending, id: 'r3', status: 'cancelled', state: 'cancelled' }

function mount() {
  const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [pending, active, cancelled] } as never)
  const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
  render(<MemoryRouter initialEntries={['/access']}><MyAccess /></MemoryRouter>)
  return { get, post }
}

// ADR 0049: a requester may withdraw a request that waits and end a grant
// that runs; each asks once, posts to its route, and reads the list again.
describe('MyAccess, the requester\'s own moves', () => {
  it('cancels a pending request through its route and reads again', async () => {
    const { get, post } = mount()
    const user = userEvent.setup()
    const row = (await screen.findByText('pending')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Cancel' }))
    const dialog = screen.getByRole('dialog', { name: 'Cancel request?' })
    expect(within(dialog).getByText('SSH · db-1')).toBeDefined()
    // The way out is Keep, so Cancel does not sit beside Cancel request (review R13).
    expect(within(dialog).getByRole('button', { name: 'Keep' })).toBeDefined()
    expect(within(dialog).queryByRole('button', { name: 'Cancel' })).toBeNull()
    await user.click(within(dialog).getByRole('button', { name: 'Cancel request' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/me/access-requests/r1/cancel', {}))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('ends an active grant through its route', async () => {
    const { post } = mount()
    const user = userEvent.setup()
    const row = (await screen.findByText('approved')).closest('tr')!
    expect(within(row).getByRole('button', { name: 'Extend…' })).toBeDefined()
    await user.click(within(row).getByRole('button', { name: 'End' }))
    const dialog = screen.getByRole('dialog', { name: 'End access?' })
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'End access' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/me/access-requests/r2/end', {}))
  })

  it('reads a cancelled request as such, with nothing to do', async () => {
    mount()
    const row = (await screen.findByText('cancelled')).closest('tr')!
    expect(within(row).queryByRole('button')).toBeNull()
  })
})
