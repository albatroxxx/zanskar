import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { Logs } from './Logs'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

const page = {
  capacity: 5000,
  seen: 12345,
  items: [
    { time: '2026-10-26T09:00:01.123Z', level: 'ERROR', msg: 'request failed', attrs: { route: 'POST /api/v1/auth/login', err: 'context canceled' } },
    { time: '2026-10-26T09:00:00.000Z', level: 'INFO', msg: 'http', attrs: { status: 200 } },
  ],
}

describe('Logs', () => {
  it('asks for info and above, shows each line with its level and attributes, and follows every five seconds', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const get = vi.spyOn(api, 'get').mockResolvedValue(page as never)
    render(<Logs />)
    expect(await screen.findByText('request failed')).toBeDefined()
    expect(get).toHaveBeenLastCalledWith('/admin/logs?level=info&limit=500')
    expect(screen.getByText('Showing 2 of the last 5000 lines kept in memory (12345 logged since start). Older lines are in the journal.')).toBeDefined()
    const row = screen.getByText('request failed').closest('tr')!
    expect(within(row).getByText('error')).toBeDefined()
    expect(within(row).getByText('route=POST /api/v1/auth/login')).toBeDefined()
    expect(within(row).getByText('err=context canceled')).toBeDefined()
    expect((screen.getByRole('link', { name: 'Download' }) as HTMLAnchorElement).getAttribute('href')).toBe('/api/v1/admin/logs/download')

    const before = get.mock.calls.length
    await vi.advanceTimersByTimeAsync(5100)
    expect(get.mock.calls.length).toBe(before + 1)

    // Follow off: no more polling.
    await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(screen.getByLabelText('Follow'))
    const after = get.mock.calls.length
    await vi.advanceTimersByTimeAsync(11000)
    expect(get.mock.calls.length).toBe(after)
  })

  it('filters by level and text, the text on Enter or the button', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ ...page, items: [] } as never)
    render(<Logs />)
    const user = userEvent.setup()
    expect(await screen.findByText('No log lines match.')).toBeDefined()
    await user.selectOptions(screen.getByLabelText('Lowest level shown'), 'warn')
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=warn&limit=500'))
    await user.type(screen.getByLabelText('Filter log lines'), ' login {Enter}')
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=warn&q=login&limit=500'))
    await user.clear(screen.getByLabelText('Filter log lines'))
    await user.type(screen.getByLabelText('Filter log lines'), 'audit')
    await user.click(screen.getByRole('button', { name: 'Filter' }))
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=warn&q=audit&limit=500'))
  })

  it('names a failed read', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(403, { code: 'forbidden', message: 'administrators only', request_id: 'r' }, '403'))
    render(<Logs />)
    expect(await screen.findByText('administrators only')).toBeDefined()
  })
})
