import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { Sessions } from '../admin/Sessions'
import { Events } from './Events'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  localStorage.clear()
})

const params = (href: string | null) => new URLSearchParams((href ?? '').split('?')[1] ?? '')

// 2026-11-03, idea 12: each list exports, as CSV, exactly what its filter
// shows, every page of it.
describe('CSV export', () => {
  it('Events exports with the filter in place, routine events left out as on the page', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/audit/verify') return { intact: true, checked: 0 } as never
      if (path === '/audit/facets') return { actions: [], object_types: [] } as never
      return { items: [] } as never
    })
    render(<MemoryRouter initialEntries={['/admin/events?outcome=failure&actor=bob']}><Events /></MemoryRouter>)
    const link = await screen.findByRole('link', { name: 'CSV' })
    expect(link.getAttribute('href')).toMatch(/^\/api\/v1\/audit\/events\.csv\?/)
    const p = params(link.getAttribute('href'))
    expect(p.get('outcome')).toBe('failure')
    expect(p.get('actor')).toBe('bob')
    expect(p.get('exclude')).toBe('audit.read,session.connect:success')
    expect(p.get('cursor')).toBeNull()
    expect(link.hasAttribute('download')).toBe(true)
  })

  it('Sessions exports with its filter in place', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    render(<MemoryRouter initialEntries={['/admin/sessions?open=1&user=alice']}><Sessions /></MemoryRouter>)
    const link = await screen.findByRole('link', { name: 'CSV' })
    const p = params(link.getAttribute('href'))
    expect(link.getAttribute('href')).toMatch(/^\/api\/v1\/sessions\.csv\?/)
    expect(p.get('open')).toBe('true')
    expect(p.get('username')).toBe('alice')
  })
})
