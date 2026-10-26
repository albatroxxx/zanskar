import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { AccessRequest } from '../../api/types'
import { MyAccess } from './MyAccess'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const soon = new Date(Date.now() + 30 * 60_000).toISOString()
const ago = new Date(Date.now() - 60_000).toISOString()

function request(over: Partial<AccessRequest>): AccessRequest {
  return { id: 'r1', user_id: 'u1', target_id: 't1', target_name: 'db-1', protocol: 'ssh', reason: 'incident 42', status: 'pending', requested_minutes: 60, created_at: '2026-10-26T08:00:00Z', ...over } as AccessRequest
}

function show(path = '/access') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <MyAccess />
    </MemoryRouter>,
  )
}

describe('MyAccess', () => {
  it('lists requests with their state, and offers to extend only a grant that is still active', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [
      request({}),
      request({ id: 'r2', status: 'approved', approved_minutes: 30, expires_at: soon, decision_note: 'keep it short' }),
      request({ id: 'r3', status: 'approved', approved_minutes: 60, expires_at: ago }),
      request({ id: 'r4', status: 'denied', target_name: undefined, asg_name: 'fleet', protocol: 'rdp', extends_request_id: 'r2' }),
    ] } as never)
    show()
    await screen.findByText('pending')
    const rows = screen.getAllByRole('row').slice(1)
    const pending = rows[0]
    expect(within(pending).getByText('incident 42')).toBeDefined()
    expect(within(pending).getByText('60 min asked')).toBeDefined()
    expect(within(pending).queryByRole('button')).toBeNull()

    expect(within(rows[1]).getByText('approved')).toBeDefined()
    expect(within(rows[1]).getByText('30 min')).toBeDefined()
    expect(within(rows[1]).getByText('(asked 60)')).toBeDefined()
    expect(within(rows[1]).getByText('Note: keep it short')).toBeDefined()
    expect(within(rows[1]).getByRole('button', { name: 'Extend…' })).toBeDefined()
    // Approved but already over: nothing to extend.
    expect(within(rows[2]).queryByRole('button')).toBeNull()
    expect(within(rows[3]).getByText('fleet')).toBeDefined()
    expect(within(rows[3]).getByText('RDP')).toBeDefined()
    expect(within(rows[3]).getByText('extension')).toBeDefined()
  })

  it('asks for an extension with the grant\'s own terms prefilled, pointing at the grant', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [request({ id: 'r2', status: 'approved', approved_minutes: 30, expires_at: soon })] } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    show()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Extend…' }))
    const dialog = screen.getByRole('dialog', { name: 'Extend access to db-1' })
    expect((within(dialog).getByLabelText('Extend by (minutes)') as HTMLInputElement).value).toBe('30')
    expect((within(dialog).getByLabelText('Reason') as HTMLTextAreaElement).value).toBe('Extension: incident 42')
    await user.clear(within(dialog).getByLabelText('Extend by (minutes)'))
    await user.type(within(dialog).getByLabelText('Extend by (minutes)'), '45')
    await user.click(within(dialog).getByRole('button', { name: 'Request extension' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/me/access-requests', { target_id: 't1', asg_id: undefined, protocol: 'ssh', reason: 'Extension: incident 42', minutes: 45, extends_request_id: 'r2' }))
    expect(await screen.findByText(/Asked to extend SSH access to db-1 by 45 minutes/)).toBeDefined()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('opens the extension from the expiry notice\'s link, and shows a refusal', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [request({ id: 'r2', status: 'approved', approved_minutes: 30, expires_at: soon })] } as never)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(422, { code: 'invalid', message: 'the policy allows at most 60 minutes', request_id: 'r' }, '422'))
    show('/access?extend=r2')
    const dialog = await screen.findByRole('dialog', { name: 'Extend access to db-1' })
    await userEvent.setup().click(within(dialog).getByRole('button', { name: 'Request extension' }))
    expect(await screen.findByText('the policy allows at most 60 minutes')).toBeDefined()
  })

  it('says when nothing was requested, and names a failed read', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    const { unmount } = show()
    expect(await screen.findByText(/You haven't requested access/)).toBeDefined()
    unmount()
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-6' }, '500'))
    show()
    expect(await screen.findByText('database is locked (reference req-6)')).toBeDefined()
  })
})
