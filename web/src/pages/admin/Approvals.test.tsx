import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { Approvals } from './Approvals'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const locked = () => new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500')

// B24: when the active grants could not be read, the page said "No active
// grants.", which an approver would take as nobody holding access.
describe('Approvals, when a list cannot be read', () => {
  it('says the active grants failed instead of that there are none', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.includes('status=approved')) throw locked()
      return { items: [] } as never
    })
    render(<Approvals />)

    expect(await screen.findByText('No requests are waiting.')).toBeDefined()
    expect(screen.queryByText('No active grants.')).toBeNull()
    expect(screen.getByText(/active grants could not be loaded: database is locked \(reference req-7\)/)).toBeDefined()
  })

  it('says the pending requests failed instead of loading forever', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.includes('status=pending')) throw locked()
      return { items: [] } as never
    })
    render(<Approvals />)

    expect(await screen.findByText('No active grants.')).toBeDefined()
    expect(screen.queryByText('Loading…')).toBeNull()
    expect(screen.getByText(/pending requests could not be loaded: database is locked \(reference req-7\)/)).toBeDefined()
  })
})
