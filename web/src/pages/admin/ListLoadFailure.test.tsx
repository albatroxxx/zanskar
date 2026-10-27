import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { Credentials } from './Credentials'
import { Policies } from './Policies'
import { Sessions } from './Sessions'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const locked = () => new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500')

// Review U3: when a list could not be read, every page showed the error and
// kept the card beneath it at "Loading…" for ever, two messages that
// contradict each other. The error stands alone now.
describe('A list page whose read failed', () => {
  it.each([
    ['Policies', Policies],
    ['Sessions', Sessions],
    ['Credentials', Credentials],
  ])('%s names the failure and does not say Loading', async (_name, Page) => {
    vi.spyOn(api, 'get').mockRejectedValue(locked())
    render(
      <MemoryRouter initialEntries={['/admin/x']}>
        <Page />
      </MemoryRouter>,
    )
    expect(await screen.findByText(/database is locked \(reference req-7\)/)).toBeDefined()
    expect(screen.queryByText('Loading…')).toBeNull()
  })
})
