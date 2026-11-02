import { cleanup, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { type ActivityRow, MyActivity } from './MyActivity'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 11: a person sees their own sign-ins, failed ones too and
// from where, and what others did to their account, by whom.
describe('Activity', () => {
  it('lists the person\'s own events in words, who did each, and from where', async () => {
    const items: ActivityRow[] = [
      { id: 3, ts: '2026-11-03T10:00:00Z', action: 'user.roles.update', outcome: 'success', ip: '', by: 'root', object_type: 'user', object_name: 'alice' },
      { id: 2, ts: '2026-11-03T09:00:00Z', action: 'user.login', outcome: 'failure', ip: '203.0.113.66', by: 'gateway', object_type: 'user', details: { reason: 'bad_password' } },
      { id: 1, ts: '2026-11-03T08:00:00Z', action: 'user.login', outcome: 'success', ip: '198.51.100.7', object_type: 'user' },
    ]
    const get = vi.spyOn(api, 'get').mockResolvedValue({ items } as never)
    render(<MemoryRouter><MyActivity /></MemoryRouter>)
    await screen.findByRole('heading', { name: 'Activity' })
    expect(get.mock.calls[0][0]).toMatch(/^\/me\/activity/)
    const rows = (await screen.findAllByRole('row')).slice(1)
    expect(rows).toHaveLength(3)
    expect(within(rows[0]).getByText('root')).toBeDefined()
    expect(rows[0].textContent).toMatch(/Updated the roles of user alice/)
    expect(rows[1].textContent).toMatch(/^.*Failed to sign in/)
    expect(within(rows[1]).queryByText('failed')).toBeNull() // the sentence says it already
    expect(within(rows[1]).getByText('203.0.113.66')).toBeDefined()
    expect(within(rows[2]).getByText('you')).toBeDefined()
    expect(within(rows[2]).getByText('198.51.100.7')).toBeDefined()
  })

  it('says so when there is nothing yet', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    render(<MemoryRouter><MyActivity /></MemoryRouter>)
    expect(await screen.findByText('Nothing yet.')).toBeDefined()
  })
})
