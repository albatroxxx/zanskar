import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Session } from '../../api/types'
import { Sessions } from './Sessions'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const ssh: Session = {
  id: 's1', user_id: 'u1', username: 'alice', target_name: 'web-01', protocol: 'ssh',
  client_ip: '127.0.0.1', started_at: '2026-11-17T10:00:00Z', state: 'live', recording_id: 'r1',
}
const cloud: Session = { ...ssh, id: 'c1', target_name: 'prod-admin', protocol: 'cloud', recording_id: 'r2' }
const ended: Session = { ...cloud, id: 'c2', state: 'ended', ended_at: '2026-11-17T10:30:00Z', recording_id: 'r3' }

function mount(path: string, answer: unknown = { events: 12, read_until: '2026-11-17T10:20:00Z' }) {
  vi.spyOn(api, 'get').mockResolvedValue({ items: [ssh, cloud, ended] } as never)
  const post = answer instanceof Error ? vi.spyOn(api, 'post').mockRejectedValue(answer) : vi.spyOn(api, 'post').mockResolvedValue(answer as never)
  render(
    <MemoryRouter initialEntries={[path]}>
      <Sessions />
    </MemoryRouter>,
  )
  return post
}

// A live cloud session's row offers Activity (ADR 0050, phase C): the read
// is asked of the gateway and its count stays beside the button; no other
// protocol has it, nor an ended session; the auditor has it as the admin
// does, since the route is the reviewer's.
describe('Sessions, Activity', () => {
  it("reads a live cloud session's activity and shows the count", async () => {
    const post = mount('/admin/sessions')
    const buttons = await screen.findAllByRole('button', { name: 'Activity' })
    expect(buttons).toHaveLength(1)
    const row = buttons[0].closest('tr')!
    expect(within(row).getByText('prod-admin')).toBeDefined()
    expect(within(row).getByRole('button', { name: 'Terminate' })).toBeDefined()
    await userEvent.setup().click(buttons[0])
    await waitFor(() => expect(post).toHaveBeenCalledWith('/sessions/c1/activity'))
    expect(await within(row).findByText('12 events')).toBeDefined()
  })

  it('says none yet, and one event in the singular', async () => {
    const post = mount('/admin/sessions', { events: 0, read_until: '2026-11-17T10:20:00Z' })
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Activity' }))
    expect(await screen.findByText('none yet')).toBeDefined()
    post.mockResolvedValue({ events: 1, read_until: '2026-11-17T10:21:00Z' } as never)
    await user.click(screen.getByRole('button', { name: 'Activity' }))
    expect(await screen.findByText('1 event')).toBeDefined()
    expect(screen.queryByText('none yet')).toBeNull()
  })

  it('offers Activity to an auditor, without Terminate', async () => {
    mount('/audit/sessions')
    expect(await screen.findAllByRole('button', { name: 'Activity' })).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Terminate' })).toBeNull()
  })

  it('shows why a read was refused', async () => {
    mount('/admin/sessions', new Error('Zanskar: the activity could not be read (the role lacks cloudtrail:LookupEvents)'))
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Activity' }))
    expect(await screen.findByText(/the role lacks cloudtrail:LookupEvents/)).toBeDefined()
    expect(screen.queryByText(/events$/)).toBeNull()
  })
})
