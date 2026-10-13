import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AuditEvent, Page } from '../../api/types'
import { Events } from './Events'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const event = (id: number, actor: string): AuditEvent => ({
  id, ts: '2026-10-06T10:00:00Z', actor_user_id: 'u' + id, actor_username: actor, actor_ip: '127.0.0.1', action: 'target.update',
  object_type: 'target', object_id: 't1', outcome: 'success', details: {}, prev_hash: '', hash: '',
})

// B30: a "Load more" still in flight when the filters changed appended its
// rows, from the old filters, to the list for the new ones.
describe('Events, Load more racing a filter change', () => {
  it('drops the page that arrives for filters no longer shown', async () => {
    let oldPage: (p: Page<AuditEvent>) => void = () => {}
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/audit/verify') return { intact: true, checked: 3, last_id: 3, last_hash: '' } as never
      if (path === '/audit/facets') return { actions: [], object_types: [] } as never
      if (path.includes('cursor=c1')) return new Promise((resolve) => { oldPage = resolve as typeof oldPage }) as never
      if (path.includes('exclude=')) return { items: [event(1, 'first-page')], next_cursor: 'c1' } as never
      return { items: [event(9, 'routine-shown')], next_cursor: '' } as never
    })
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Load more' }))
    await user.click(screen.getByRole('checkbox', { name: /Show routine events/ }))
    expect(await screen.findByText('routine-shown')).toBeDefined()

    oldPage({ items: [event(2, 'older-under-old-filters')], next_cursor: 'c2' })
    // Apply is held off while a Load more is in flight: back on, it has landed.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply filters' }).hasAttribute('disabled')).toBe(false))

    expect(screen.queryByText('older-under-old-filters')).toBeNull()
    expect(screen.getByText('routine-shown')).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
  })
})
