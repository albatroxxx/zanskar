import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { Recordings } from './Recordings'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 5 (ADR 0041): "who ran systemctl stop nginx?" across every
// terminal recording kept; each hit opens the recording at that command.
describe('Recordings, find a command', () => {
  it('asks the gateway and links each hit to its moment', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/recordings/search')) {
        return { items: [{ recording_id: 'r1', session_id: 's1', username: 'alice', target_name: 'web-1', protocol: 'ssh', started_at: '2026-11-02T10:00:00Z', seq: 3, at_ms: 65_000, command: 'sudo systemctl stop nginx' }] } as never
      }
      return { items: [] } as never
    })
    render(<MemoryRouter initialEntries={['/admin/recordings']}><Recordings /></MemoryRouter>)
    const user = userEvent.setup()
    const find = screen.getByRole('button', { name: 'Find' }) as HTMLButtonElement
    await user.type(screen.getByLabelText('Find a command'), 's')
    expect(find.disabled).toBe(true) // one letter finds too much
    await user.type(screen.getByLabelText('Find a command'), 'ystemctl stop')
    await user.click(find)
    expect(get.mock.calls.map((c) => c[0])).toContain('/recordings/search?q=systemctl+stop')
    expect(await screen.findByText('sudo systemctl stop nginx')).toBeDefined()
    expect(screen.getByRole('link', { name: 'Review, opens in a new tab' }).getAttribute('href')).toBe('/admin/recordings/r1?marker=3')
  })

  it('says when nothing matches', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    render(<MemoryRouter initialEntries={['/admin/recordings']}><Recordings /></MemoryRouter>)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Find a command'), 'rm -rf{Enter}')
    expect(await screen.findByText('No command matches.')).toBeDefined()
  })
})
