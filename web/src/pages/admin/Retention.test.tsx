import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { Retention } from './Retention'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const GiB = 1024 * 1024 * 1024

describe('Retention', () => {
  it('shows the stored policy in days and GiB, warns while both are off, and saves in bytes', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ max_age_days: 0, max_total_bytes: 0 } as never)
    const put = vi.spyOn(api, 'put').mockResolvedValue({ max_age_days: 90, max_total_bytes: 1.5 * GiB, updated_at: '2026-10-26T09:00:00Z' } as never)
    render(<Retention />)
    const user = userEvent.setup()
    expect(await screen.findByText(/Retention is off: recordings are kept forever/)).toBeDefined()

    const days = screen.getByLabelText('Keep recordings for (days)')
    const cap = screen.getByLabelText('Total size cap (GiB)')
    await user.clear(days)
    await user.type(days, '90')
    expect(screen.queryByText(/Retention is off/)).toBeNull()
    await user.clear(cap)
    await user.type(cap, '1.5')
    await user.click(screen.getByRole('button', { name: 'Save policy' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/admin/retention', { max_age_days: 90, max_total_bytes: 1.5 * GiB }))
    expect(await screen.findByText('Retention policy saved.')).toBeDefined()
    expect(screen.getByText(/Last changed /)).toBeDefined()
    expect((cap as HTMLInputElement).value).toBe('1.5')
  })

  it('shows the stored values and the server\'s refusal', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ max_age_days: 30, max_total_bytes: 2 * GiB } as never)
    vi.spyOn(api, 'put').mockRejectedValue(new ApiError(422, { code: 'invalid', message: 'max_age_days must be at most 3650', request_id: 'r' }, '422'))
    render(<Retention />)
    const user = userEvent.setup()
    const days = await screen.findByLabelText('Keep recordings for (days)')
    expect((days as HTMLInputElement).value).toBe('30')
    expect((screen.getByLabelText('Total size cap (GiB)') as HTMLInputElement).value).toBe('2')
    await user.clear(days)
    await user.type(days, '9999')
    await user.click(screen.getByRole('button', { name: 'Save policy' }))
    expect(await screen.findByText('max_age_days must be at most 3650')).toBeDefined()
    expect(screen.queryByText('Retention policy saved.')).toBeNull()
  })

  it('names a failed read instead of loading forever', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-4' }, '500'))
    render(<Retention />)
    expect(await screen.findByText('database is locked (reference req-4)')).toBeDefined()
    expect(screen.queryByText('Loading…')).toBeNull()
  })
})
