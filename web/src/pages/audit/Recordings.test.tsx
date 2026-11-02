import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { Session } from '../../api/types'
import { Recordings } from './Recordings'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const session = (i: number, over: Partial<Session> = {}): Session => ({
  id: 's' + i, user_id: 'u1', username: 'alice', target_name: 'web-01', protocol: 'ssh', client_ip: '127.0.0.1', started_at: '2026-10-06T10:00:00Z', ...over,
})

function page(items: Session[], next = '') {
  vi.spyOn(api, 'get').mockResolvedValue({ items, next_cursor: next } as never)
  render(
    <MemoryRouter initialEntries={['/audit/recordings']}>
      <Recordings />
    </MemoryRouter>,
  )
}

// 2026-11-01: each row had Review, Download and Transcript; the recording's
// page, which Review opens, has the downloads, so a row has Review alone.
describe('Recordings, a row', () => {
  it('offers Review alone, the downloads being on the recording’s page', async () => {
    page([session(1, { recording_id: 'r1', protocol: 'http', target_name: 'wiki' }), session(2, { recording_id: 'r2', protocol: 'ssh' })])
    await screen.findAllByRole('link', { name: 'Review, opens in a new tab' })
    for (const row of screen.getAllByRole('row').slice(1)) {
      expect(Array.from(row.querySelectorAll('a, button')).map((a) => a.textContent)).toEqual(['Review'])
    }
    expect(document.querySelector('a[href$="/download"], a[href$="/transcript"]')).toBeNull()
  })

  // 2026-11-03 live audit, Q10: the global policy said 1 day while October
  // recordings stayed, kept by their own dates; each row now says when it goes.
  it('says when each recording goes, or that it is gone', async () => {
    const ended = '2026-10-06T10:05:00Z'
    page([
      session(1, { recording_id: 'r1', ended_at: ended, recording_kept_until: '2026-12-01T00:00:00Z' }),
      session(2, { recording_id: 'r2', ended_at: ended, recording_purged: true }),
      session(3, { recording_id: 'r3', ended_at: ended }),
      session(4, { recording_id: 'r4' }),
    ])
    expect(await screen.findByRole('columnheader', { name: 'Kept until' })).toBeDefined()
    const cells = screen.getAllByRole('row').slice(1).map((r) => r.querySelectorAll('td')[6].textContent)
    expect(cells[0]).toMatch(/2026/)
    expect(cells.slice(1)).toEqual(['Deleted', 'No age limit', '—'])
  })

  it('writes the protocol the way every other page does', async () => {
    page([session(1, { recording_id: 'r1', protocol: 'winrm' }), session(2, { recording_id: 'r2', protocol: 'ssh' })])
    expect(await screen.findByRole('cell', { name: 'WinRM' })).toBeDefined()
    expect(screen.getByRole('cell', { name: 'SSH' })).toBeDefined()
  })
})

// B24: the page reads the newest sessions a page at a time and filters them
// in the browser, so with older sessions still unread it said "No recordings
// yet." or "No recordings match." about sessions it had never looked at.
describe('Recordings', () => {
  it('says how far back it looked when the loaded sessions hold no recording', async () => {
    page(Array.from({ length: 100 }, (_, i) => session(i)), 'c1')

    expect(await screen.findByRole('button', { name: 'Load more' })).toBeDefined()
    expect(screen.queryByText('No recordings yet.')).toBeNull()
    expect(screen.getByText(/No recordings among the newest 100 sessions\. Load more to look further back\./)).toBeDefined()
  })

  it('says the filter searched only the sessions loaded so far', async () => {
    page([session(1, { recording_id: 'r1' }), session(2), session(3, { recording_id: 'r3' })], 'c1')
    await screen.findAllByRole('link', { name: 'Review, opens in a new tab' })

    await userEvent.setup().type(screen.getByLabelText('Filter recordings'), 'bob')
    expect(screen.queryByText('No recordings match.')).toBeNull()
    expect(screen.getByText(/No recordings among the newest 3 sessions match\. Load more to search further back\./)).toBeDefined()

    await userEvent.setup().clear(screen.getByLabelText('Filter recordings'))
    expect(screen.getByText(/Showing recordings from the newest 3 sessions; the filter searches only these\./)).toBeDefined()
  })

  it('keeps the plain answers once every session is loaded', async () => {
    page([session(1)])
    expect(await screen.findByText('No recordings yet.')).toBeDefined()
    expect(screen.queryByText(/newest/)).toBeNull()
  })

  it('shows a failed load as the error, not as loading', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500'))
    render(
      <MemoryRouter initialEntries={['/audit/recordings']}>
        <Recordings />
      </MemoryRouter>,
    )
    expect(await screen.findByText('database is locked (reference req-7)')).toBeDefined()
    expect(screen.queryByText('Loading…')).toBeNull()
  })
})
