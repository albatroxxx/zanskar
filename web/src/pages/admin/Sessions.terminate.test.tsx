import { cleanup, render, screen, within } from '@testing-library/react'
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

const live: Session = {
  id: 's1', user_id: 'u1', username: 'alice', target_name: 'web-01', protocol: 'ssh',
  client_ip: '127.0.0.1', started_at: '2026-10-06T10:00:00Z', recording_id: 'r1',
}

function mount() {
  const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [live] } as never)
  const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
  render(
    <MemoryRouter initialEntries={['/admin/sessions']}>
      <Sessions />
    </MemoryRouter>,
  )
  return { get, post }
}

// Review finding F1: the terminate body always empty passed both Sessions
// tests, which only checked which buttons render. The reason an administrator
// types is what the audit log keeps, so it has to reach the gateway.
describe('Sessions, Terminate', () => {
  it('sends the reason typed into the dialog and reloads the list', async () => {
    const { get, post } = mount()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Terminate' }))
    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText(/Reason/), 'change window closed')
    await user.click(within(dialog).getByRole('button', { name: 'Terminate' }))
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/sessions/s1/terminate', { reason: 'change window closed' })
    expect(get.mock.calls.length).toBeGreaterThan(1)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('sends an empty body when no reason is given', async () => {
    const { post } = mount()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Terminate' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Terminate' }))
    expect(post).toHaveBeenCalledWith('/sessions/s1/terminate', {})
  })

  it('shows why a terminate was refused', async () => {
    mount()
    vi.spyOn(api, 'post').mockRejectedValue(new Error('session already ended'))
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Terminate' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Terminate' }))
    // The dialog shows it and the page keeps it once the dialog is gone.
    expect((await screen.findAllByText(/session already ended/)).length).toBeGreaterThan(0)
  })
})
