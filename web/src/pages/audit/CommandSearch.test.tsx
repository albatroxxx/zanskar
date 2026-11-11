import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
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

  // The owner, 2026-11-11: the hits of a search stayed above the recordings
  // with no way to put them away but reloading, and with the box changed
  // they no longer said what they were for.
  it('says what its hits are for, and puts them away with Clear, Esc or an empty box', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/recordings/search')) {
        return { items: [{ recording_id: 'r1', session_id: 's1', username: 'alice', target_name: 'web-1', protocol: 'ssh', started_at: '2026-11-02T10:00:00Z', seq: 1, at_ms: 1000, command: 'ls -la' }] } as never
      }
      return { items: [] } as never
    })
    render(<MemoryRouter initialEntries={['/admin/recordings']}><Recordings /></MemoryRouter>)
    const user = userEvent.setup()
    const box = screen.getByLabelText('Find a command') as HTMLInputElement
    const find = async () => {
      await user.clear(box)
      await user.type(box, 'ls{Enter}')
      await screen.findByText('ls -la')
    }

    await find()
    expect(screen.getByText('1 match for')).toBeDefined()
    await user.type(box, ' -la') // the box now says another thing; the hits keep their own term
    expect(screen.getByText('ls', { selector: 'span.mono' })).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Clear' }))
    expect(screen.queryByText('ls -la')).toBeNull()
    expect(box.value).toBe('')
    expect(document.activeElement).toBe(box)

    await find()
    await user.keyboard('{Escape}')
    expect(screen.queryByText('ls -la')).toBeNull()
    expect(box.value).toBe('')

    await find()
    await user.clear(box)
    expect(screen.queryByText('ls -la')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull()
  })
})

// 2026-11-03, idea 5 (ADR 0041 amendment): what a session printed, found
// the same way; each hit says the command it followed and opens the
// recording at the moment it was printed.
describe('Recordings, find printed text', () => {
  const hit = { recording_id: 'r2', session_id: 's2', username: 'bob', target_name: 'web-2', protocol: 'ssh', started_at: '2026-11-02T10:00:00Z', at_ms: 8_000, line: 'nginx: bind() to 0.0.0.0:443 failed', after: 'journalctl -u nginx' }

  it('asks for output and links each hit to its moment', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/recordings/search')) return { items: [hit] } as never
      return { items: [] } as never
    })
    render(<MemoryRouter initialEntries={['/admin/recordings']}><Recordings /></MemoryRouter>)
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Search in'), 'output')
    await user.type(screen.getByLabelText('Find printed text'), 'bind(){Enter}')
    expect(get.mock.calls.map((c) => c[0])).toContain('/recordings/search?q=bind%28%29&in=output')
    expect(await screen.findByText('nginx: bind() to 0.0.0.0:443 failed')).toBeDefined()
    expect(screen.getByText('after journalctl -u nginx')).toBeDefined()
    expect(screen.getByRole('columnheader', { name: 'Printed' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'Review, opens in a new tab' }).getAttribute('href')).toBe('/admin/recordings/r2?at=8000')
  })

  it('says when nothing printed matches, and why output cannot be searched', async () => {
    let refuse = false
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/recordings/search') && refuse) {
        throw new ApiError(409, { code: 'output_not_indexed', message: 'terminal output is not indexed: the setting Index terminal output is off' }, '409')
      }
      return { items: [] } as never
    })
    render(<MemoryRouter initialEntries={['/admin/recordings']}><Recordings /></MemoryRouter>)
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Search in'), 'output')
    await user.type(screen.getByLabelText('Find printed text'), 'segfault{Enter}')
    expect(await screen.findByText('No output matches.')).toBeDefined()
    refuse = true
    await user.click(screen.getByRole('button', { name: 'Find' }))
    expect(await screen.findByText(/the setting Index terminal output is off/)).toBeDefined()
    expect(screen.queryByText('No output matches.')).toBeNull()
  })

  it('keeps a hit list to the kind it was found in', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.includes('in=output')) return { items: [hit] } as never
      return { items: [] } as never
    })
    render(<MemoryRouter initialEntries={['/admin/recordings']}><Recordings /></MemoryRouter>)
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Search in'), 'output')
    await user.type(screen.getByLabelText('Find printed text'), 'bind{Enter}')
    await screen.findByText('nginx: bind() to 0.0.0.0:443 failed')
    // Switching back shows the output hits until the next search.
    await user.selectOptions(screen.getByLabelText('Search in'), 'commands')
    expect(screen.getByText('nginx: bind() to 0.0.0.0:443 failed')).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Find' }))
    expect(await screen.findByText('No command matches.')).toBeDefined()
  })
})
