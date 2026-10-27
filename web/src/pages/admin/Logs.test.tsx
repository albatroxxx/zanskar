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
    expect(get).toHaveBeenLastCalledWith('/admin/logs?level=info&limit=100')
    expect(screen.getByText('Showing 2 of the last 5000 lines kept in memory (12345 logged since start). Older lines are in the journal.')).toBeDefined()
    const row = screen.getByText('request failed').closest('tr')!
    expect(within(row).getByText('error')).toBeDefined()
    expect(within(row).getByText('route=POST /api/v1/auth/login')).toBeDefined()
    expect(within(row).getByText('err=context canceled')).toBeDefined()
    expect((screen.getByRole('link', { name: 'Download' }) as HTMLAnchorElement).getAttribute('href')).toBe('/api/v1/admin/logs/download')

    // Real time advances these timers too; a slow runner may cross a second tick.
    const before = get.mock.calls.length
    await vi.advanceTimersByTimeAsync(5100)
    expect(get.mock.calls.length).toBeGreaterThanOrEqual(before + 1)

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
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=warn&limit=100'))
    await user.type(screen.getByLabelText('Filter log lines'), ' login {Enter}')
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=warn&q=login&limit=100'))
    await user.clear(screen.getByLabelText('Filter log lines'))
    await user.type(screen.getByLabelText('Filter log lines'), 'audit')
    await user.click(screen.getByRole('button', { name: 'Filter' }))
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=warn&q=audit&limit=100'))
  })

  it('names a failed read', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(403, { code: 'forbidden', message: 'administrators only', request_id: 'r' }, '403'))
    render(<Logs />)
    expect(await screen.findByText('administrators only')).toBeDefined()
  })
})


// Review U8: the page asked for 500 lines, a 20,000 px scroll by default. It
// asks for 100 and offers more while the ring holds more than it shows.
describe('Logs, the page size', () => {
  it('starts at 100 lines and asks for 200 more on request, up to what the ring keeps', async () => {
    // The ring holds 350 lines and answers with as many as were asked for.
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      const limit = Number(new URLSearchParams(path.slice(path.indexOf('?') + 1)).get('limit'))
      return { ...page, capacity: 350, items: Array.from({ length: Math.min(limit, 350) }, (_, i) => ({ time: '2026-10-26T09:00:00.000Z', level: 'INFO', msg: 'line ' + i, attrs: {} })) } as never
    })
    render(<Logs />)
    expect(await screen.findByText('line 0')).toBeDefined()
    expect(get).toHaveBeenLastCalledWith('/admin/logs?level=info&limit=100')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Show more' }))
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=info&limit=300'))
    await user.click(screen.getByRole('button', { name: 'Show more' }))
    await waitFor(() => expect(get).toHaveBeenLastCalledWith('/admin/logs?level=info&limit=350'))
    expect(screen.queryByRole('button', { name: 'Show more' })).toBeNull()
  })

  it('offers no more when the ring holds fewer lines than the page', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(page as never)
    render(<Logs />)
    expect(await screen.findByText('request failed')).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Show more' })).toBeNull()
  })
})
