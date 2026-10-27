import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AccessRequest } from '../../api/types'
import { Approvals } from './Approvals'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const pending: AccessRequest = {
  id: 'r1', user_id: 'u1', username: 'bob', target_id: 't1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy',
  requested_minutes: 60, status: 'pending', created_at: '2026-10-26T10:00:00Z', updated_at: '2026-10-26T10:00:00Z',
}
const active: AccessRequest = {
  ...pending, id: 'r2', username: 'carol', status: 'approved', approved_minutes: 30, expires_at: '2026-10-26T11:00:00Z',
}

function mount() {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.includes('status=pending') ? [pending] : [active] }) as never)
  const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
  render(<Approvals />)
  return post
}

// Review Q1/Q2 finding F1: Deny calling the approve endpoint passed every
// test, because approve, deny and revoke were never clicked. Each decision
// now has to reach its own endpoint with its own body.
describe('Approvals, the decisions', () => {
  it('denies through the deny endpoint, with no body of consequence', async () => {
    const post = mount()
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Deny' }))
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/access-requests/r1/deny', {})
  })

  it('approves through the approve endpoint with the minutes and note the approver chose', async () => {
    const post = mount()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Approve…' }))
    const dialog = screen.getByRole('dialog')
    const minutes = within(dialog).getByLabelText('Grant (minutes)')
    expect((minutes as HTMLInputElement).value).toBe('60')
    await user.clear(minutes)
    await user.type(minutes, '45')
    await user.type(within(dialog).getByLabelText(/Note/), 'until the deploy is done')
    await user.click(within(dialog).getByRole('button', { name: /Approve for 45 min/ }))
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/access-requests/r1/approve', { minutes: 45, note: 'until the deploy is done' })
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('revokes an active grant through the revoke endpoint', async () => {
    const post = mount()
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Revoke' }))
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/access-requests/r2/revoke', {})
  })

  it('shows the refusal when a decision fails and keeps the row', async () => {
    mount()
    vi.spyOn(api, 'post').mockRejectedValue(new Error('policy no longer grants this'))
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Deny' }))
    expect(await screen.findByText(/policy no longer grants this/)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Deny' })).toBeDefined()
  })
})
