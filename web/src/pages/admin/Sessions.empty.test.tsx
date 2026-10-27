import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { Sessions } from './Sessions'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// Review U5: with nothing filtered the empty list said "No sessions match.",
// as if a filter had hidden them. It says so only once a filter applies.
describe('Sessions, the empty state', () => {
  it('says there are none yet, and that none match only under a filter', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    render(
      <MemoryRouter initialEntries={['/admin/sessions']}>
        <Sessions />
      </MemoryRouter>,
    )
    expect(await screen.findByText('No sessions yet.')).toBeDefined()
    await userEvent.setup().click(screen.getByLabelText('Live only'))
    expect(await screen.findByText('No sessions match.')).toBeDefined()
  })
})
