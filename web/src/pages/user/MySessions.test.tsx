import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Session } from '../../api/types'
import { MySessions } from './MySessions'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const session = (id: string): Session => ({ id, user_id: 'u1', target_name: 'web-1', protocol: 'ssh', client_ip: '10.0.0.1', started_at: '2026-10-06T10:00:00Z' })

// Load more stayed enabled while the next page was on its way, so a
// double-click asked for it twice and the list showed it twice. The Events
// and Recordings pages already held theirs off.
describe('My sessions, Load more', () => {
  it('asks for the next page once, however fast it is clicked', async () => {
    let answer: () => void = () => {}
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (!path.includes('cursor=')) return { items: [session('a')], next_cursor: 'c1' } as never
      await new Promise<void>((resolve) => {
        answer = resolve
      })
      return { items: [session('b')] } as never
    })
    render(<MemoryRouter><MySessions /></MemoryRouter>)
    const user = userEvent.setup()

    await user.dblClick(await screen.findByRole('button', { name: 'Load more' }))
    answer()

    await waitFor(() => expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull())
    expect(get.mock.calls.filter(([path]) => String(path).includes('cursor=')).length).toBe(1)
    expect(screen.getAllByRole('row')).toHaveLength(3) // the header and two sessions
  })
})
