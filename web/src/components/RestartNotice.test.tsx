import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import type { SystemStatus } from '../api/types'
import { RestartNotice } from './RestartNotice'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

function status(over: Partial<SystemStatus> = {}): SystemStatus {
  return { version: '1.5.0', started_at: '2026-10-26T08:00:00Z', uptime_seconds: 3600, supervisor: 'systemd', live_sessions: 0, env_file: { state: 'unchanged', checked_at: '2026-10-26T09:00:00Z' }, restart_required: false, draining: false, ...over }
}

describe('RestartNotice', () => {
  it('stays silent while nothing changed', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue(status() as never)
    const { container } = render(<RestartNotice />)
    await waitFor(() => expect(get).toHaveBeenCalledWith('/admin/system/status'))
    expect(container.textContent).toBe('')
  })

  it('names the changed variables, never their values, and restarts after a confirmation that counts the live sessions', async () => {
    // The banner polls the status; after the restart is asked for, the poll
    // answers with the drain too, as the gateway would.
    let current = status({ restart_required: true, live_sessions: 2, env_file: { state: 'changed', path: '/etc/zanskar/env', changed: ['ZANSKAR_LISTEN_ADDR', 'ZANSKAR_LOG_LEVEL'], checked_at: 'x' } })
    vi.spyOn(api, 'get').mockImplementation(async () => current as never)
    const post = vi.spyOn(api, 'post').mockImplementation(async () => {
      current = status({ draining: true, live_sessions: 2, drain: { requested_at: 'x', requested_by: 'u1', deadline: '2026-10-26T09:15:00Z', wait_minutes: 15 } })
      return current as never
    })
    render(<RestartNotice />)
    const user = userEvent.setup()
    expect(await screen.findByText('Restart required.')).toBeDefined()
    expect(screen.getByText(/ZANSKAR_LISTEN_ADDR, ZANSKAR_LOG_LEVEL changed in \/etc\/zanskar\/env/)).toBeDefined()
    expect(screen.queryByText(/ZANSKAR_MASTER_KEY/)).toBeNull()
    expect(screen.getByText(/2 live sessions now\. systemd starts the service again/)).toBeDefined()

    await user.click(screen.getByRole('button', { name: 'Restart the gateway…' }))
    const dialog = screen.getByRole('dialog', { name: 'Restart the gateway?' })
    expect(within(dialog).getByText(/2 live sessions would be cut off by an immediate restart/)).toBeDefined()
    const minutes = dialog.querySelector('#rs-min') as HTMLInputElement
    expect(minutes.value).toBe('15')
    await user.clear(minutes)
    await user.type(minutes, '999')
    expect(minutes.value).toBe('240')
    await user.click(within(dialog).getByRole('button', { name: 'Restart' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/system/restart', { wait_minutes: 240 }))
    expect(await screen.findByText('Restarting.')).toBeDefined()
    expect(screen.getByText(/Waiting for 2 live sessions to end, until/)).toBeDefined()
  })

  it('restarts at once when asked to, and lets a drain be cancelled', async () => {
    const pending = status({ restart_required: true, env_file: { state: 'changed', path: '/etc/zanskar/env', changed: ['ZANSKAR_TLS_HOSTS'], checked_at: 'x' } })
    let current = pending
    vi.spyOn(api, 'get').mockImplementation(async () => current as never)
    const post = vi.spyOn(api, 'post').mockImplementation(async () => {
      current = status({ draining: true, live_sessions: 0, drain: { requested_at: 'x', requested_by: 'u1', deadline: 'x', wait_minutes: 0 } })
      return current as never
    })
    const del = vi.spyOn(api, 'del').mockImplementation(async () => {
      current = pending
      return current as never
    })
    render(<RestartNotice />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Restart the gateway…' }))
    const dialog = screen.getByRole('dialog', { name: 'Restart the gateway?' })
    expect(within(dialog).getByText(/No session is live, so a restart is quick/)).toBeDefined()
    await user.click(within(dialog).getByLabelText('End live sessions and restart now'))
    await user.click(within(dialog).getByRole('button', { name: 'Restart' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/system/restart', { wait_minutes: 0 }))
    expect(await screen.findByText(/No session is live; the gateway is stopping now/)).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Cancel restart' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/admin/system/restart'))
    expect(await screen.findByText('Restart required.')).toBeDefined()
  })

  // The first answer brings the start time; with it among the effect's
  // dependencies the notice read the status again straight away, on every
  // admin page (the live console, 2026-11-01).
  it('reads the status once as a page opens', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue(status() as never)
    render(<RestartNotice />)
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1))
    await new Promise((r) => setTimeout(r, 50))
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('takes its own restart as the latest answer: the gateway gone next is a restart under way', async () => {
    const pending = status({ restart_required: true, env_file: { state: 'changed', path: '/etc/zanskar/env', changed: ['ZANSKAR_TLS_HOSTS'], checked_at: 'x' } })
    // the page's first read, then the gateway is away
    vi.spyOn(api, 'get').mockResolvedValueOnce(pending as never).mockRejectedValue(new Error('Failed to fetch'))
    vi.spyOn(api, 'post').mockResolvedValue(status({ draining: true, live_sessions: 0, drain: { requested_at: 'x', requested_by: 'u1', deadline: 'x', wait_minutes: 0 } }) as never)
    render(<RestartNotice />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Restart the gateway…' }))
    const dialog = screen.getByRole('dialog', { name: 'Restart the gateway?' })
    await user.click(within(dialog).getByLabelText('End live sessions and restart now'))
    await user.click(within(dialog).getByRole('button', { name: 'Restart' }))
    expect(await screen.findByText(/Restarting the gateway… this page reloads when it is back/)).toBeDefined()
  })

  it('warns in red when the master key changed, and says when the file cannot be checked', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(status({ restart_required: true, env_file: { state: 'changed', path: '/etc/zanskar/env', changed: ['ZANSKAR_MASTER_KEY'], checked_at: 'x' } }) as never)
    const { unmount } = render(<RestartNotice />)
    expect(await screen.findByText('ZANSKAR_MASTER_KEY differs.')).toBeDefined()
    expect(screen.getByText(/a restart cannot open stored secrets/)).toBeDefined()
    unmount()
    vi.spyOn(api, 'get').mockResolvedValue(status({ env_file: { state: 'unreadable', path: '/etc/zanskar/env', error: 'permission denied', checked_at: 'x' } }) as never)
    render(<RestartNotice />)
    expect(await screen.findByText('Cannot check /etc/zanskar/env for changes.')).toBeDefined()
    expect(screen.getByText(/permission denied/)).toBeDefined()
  })

  it('keeps a refused restart in the dialog', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(status({ restart_required: true, env_file: { state: 'changed', path: '/etc/zanskar/env', changed: ['ZANSKAR_TLS_HOSTS'], checked_at: 'x' } }) as never)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(409, { code: 'draining', message: 'a restart is already under way', request_id: 'r' }, '409'))
    render(<RestartNotice />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Restart the gateway…' }))
    const dialog = screen.getByRole('dialog', { name: 'Restart the gateway?' })
    await user.click(within(dialog).getByRole('button', { name: 'Restart' }))
    expect(await within(dialog).findByText('a restart is already under way')).toBeDefined()
  })

  it('polls while the gateway is away and reloads once a fresh process answers', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const draining = status({ draining: true, live_sessions: 0, drain: { requested_at: 'x', requested_by: 'u1', deadline: 'x', wait_minutes: 0 } })
    const get = vi.spyOn(api, 'get')
      .mockResolvedValueOnce(draining as never)
      .mockRejectedValueOnce(new Error('Failed to fetch'))
      .mockResolvedValueOnce(status({ started_at: '2026-10-26T09:05:00Z' }) as never)
    const reload = vi.fn()
    const original = window.location
    Object.defineProperty(window, 'location', { configurable: true, value: { ...original, reload } })
    try {
      render(<RestartNotice />)
      expect(await screen.findByText('Restarting.')).toBeDefined()
      await vi.advanceTimersByTimeAsync(2100)
      expect(await screen.findByText(/Restarting the gateway… this page reloads when it is back/)).toBeDefined()
      await vi.advanceTimersByTimeAsync(2100)
      await waitFor(() => expect(reload).toHaveBeenCalled())
      expect(get.mock.calls.length).toBeGreaterThanOrEqual(3)
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
  })
})
