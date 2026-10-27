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

// A desktop recording is a pixel stream with no command lines, an
// application's (ADR 0034) included: Review and Download, no Transcript.
describe('Recordings of desktops', () => {
  it('offers no transcript for an application session', async () => {
    page([session(1, { recording_id: 'r1', protocol: 'http', target_name: 'wiki' }), session(2, { recording_id: 'r2', protocol: 'ssh' })])
    await screen.findAllByRole('link', { name: 'Review' })
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows[0].textContent).toContain('HTTP')
    expect(rows[0].querySelector('a[href$="/transcript"]')).toBeNull()
    expect(rows[0].querySelector('a[href$="/download"]')).not.toBeNull()
    expect(rows[1].querySelector('a[href$="/transcript"]')).not.toBeNull()
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
    await screen.findAllByRole('link', { name: 'Review' })

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
