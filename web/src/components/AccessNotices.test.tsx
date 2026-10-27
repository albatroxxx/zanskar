import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import type { AccessRequest } from '../api/types'
import { AccessNotices } from './AccessNotices'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const grant = (id: string, over: Partial<AccessRequest>): AccessRequest => ({
  id, user_id: 'u1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy', requested_minutes: 60, approved_minutes: 60,
  status: 'approved', created_at: '2026-10-26T09:00:00Z', updated_at: '2026-10-26T09:00:00Z', ...over,
})

function mount(grants: AccessRequest[]) {
  vi.spyOn(api, 'get').mockResolvedValue({ items: grants } as never)
  render(
    <MemoryRouter>
      <AccessNotices />
    </MemoryRouter>,
  )
}

const min = 60_000
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString()

// Review finding F1: the "expiring soon" comparison inverted passed every
// test, because nothing rendered the notices with a grant. The component is
// at 8% branch coverage for the same reason.
describe('AccessNotices', () => {
  it('warns about a grant that ends within ten minutes, with a link to extend it', async () => {
    mount([grant('r1', { expires_at: iso(5 * min), decided_at: iso(-50 * min) })])
    expect(await screen.findByText(/ends in about/)).toBeDefined()
    expect(screen.getByText(/5 min/)).toBeDefined()
    expect(screen.getByRole('link', { name: 'Ask to extend it' }).getAttribute('href')).toBe('/access?extend=r1')
  })

  it('says nothing about a grant that already ended or one with a long way to go', async () => {
    mount([
      grant('over', { expires_at: iso(-5 * min), decided_at: iso(-70 * min) }),
      grant('plenty', { expires_at: iso(55 * min), decided_at: iso(-30 * min) }),
    ])
    // Give the poll a turn to land, then there must be no notice at all.
    await new Promise((r) => setTimeout(r, 20))
    expect(screen.queryByText(/ends in about/)).toBeNull()
    expect(screen.queryByText(/was approved/)).toBeNull()
  })

  it('announces a fresh approval with the minutes the approver gave', async () => {
    mount([grant('r2', { expires_at: iso(45 * min), decided_at: iso(-2 * min), approved_minutes: 45, requested_minutes: 60 })])
    expect(await screen.findByText(/was approved for/)).toBeDefined()
    expect(screen.getByText('45 minutes')).toBeDefined()
    expect(screen.getByText(/you asked for 60/)).toBeDefined()
  })

  it('can be dismissed, and stays dismissed', async () => {
    mount([grant('r1', { expires_at: iso(5 * min), decided_at: iso(-50 * min) })])
    await screen.findByText(/ends in about/)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByText(/ends in about/)).toBeNull()
  })
})
