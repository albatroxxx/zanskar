import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import type { AccessRequest } from '../api/types'
import { GrantClock, grantFor } from './GrantClock'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 6: a session on a just-in-time grant shows how long is
// left and asks for more time without leaving the session.

const inMin = (m: number) => new Date(Date.now() + m * 60_000).toISOString()
const grant = (over: Partial<AccessRequest> = {}): AccessRequest =>
  ({ id: 'g1', user_id: 'u', target_id: 't1', protocol: 'ssh', reason: 'patch', requested_minutes: 60, status: 'approved', expires_at: inMin(8), ...over }) as AccessRequest

describe('grantFor', () => {
  it('picks the person\'s active grant for this target and protocol, ending last', () => {
    const now = Date.now()
    const s = { target_id: 't1', protocol: 'ssh' }
    expect(grantFor([grant({ protocol: 'rdp' }), grant({ target_id: 't2' }), grant({ expires_at: inMin(-1) }), grant({ status: 'pending' })], s, now)).toBeNull()
    expect(grantFor([grant({ id: 'a', expires_at: inMin(5) }), grant({ id: 'b', expires_at: inMin(50) })], s, now)?.id).toBe('b')
    // A group's session matches by group.
    expect(grantFor([grant({ target_id: undefined, asg_id: 'g' })], { asg_id: 'g', protocol: 'ssh' }, now)?.id).toBe('g1')
  })
})

describe('GrantClock', () => {
  it('says how long is left near the end and asks for more time as an extension of the grant', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [grant()] } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    render(<GrantClock session={{ target_id: 't1', protocol: 'ssh' }} />)
    expect(await screen.findByText(/access ends in 8 min/)).toBeDefined()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Ask for more time' }))
    await user.selectOptions(screen.getByLabelText('More minutes'), '30')
    await user.type(screen.getByLabelText('Why'), 'reboot still running')
    await user.click(screen.getByRole('button', { name: 'Ask' }))
    expect(post).toHaveBeenCalledWith('/me/access-requests', { target_id: 't1', asg_id: undefined, protocol: 'ssh', reason: 'reboot still running', minutes: 30, extends_request_id: 'g1' })
  })

  it('says more time is asked while the extension waits', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [grant(), grant({ id: 'x', status: 'pending', extends_request_id: 'g1', expires_at: undefined })] } as never)
    render(<GrantClock session={{ target_id: 't1', protocol: 'ssh' }} />)
    expect(await screen.findByText('more time asked; waiting for approval')).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Ask for more time' })).toBeNull()
  })

  it('shows nothing on standing access, or far from the end', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    const { unmount } = render(<GrantClock session={{ target_id: 't1', protocol: 'ssh' }} />)
    await vi.waitFor(() => expect(get).toHaveBeenCalled())
    expect(screen.queryByText(/access ends/)).toBeNull()
    unmount()
    get.mockResolvedValue({ items: [grant({ expires_at: inMin(45) })] } as never)
    render(<GrantClock session={{ target_id: 't1', protocol: 'ssh' }} />)
    await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(2))
    expect(screen.queryByText(/access ends/)).toBeNull()
  })
})
