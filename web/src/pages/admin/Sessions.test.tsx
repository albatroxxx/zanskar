import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Session } from '../../api/types'
import { Sessions } from './Sessions'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const live: Session = {
  id: 's1', user_id: 'u1', username: 'alice', target_name: 'web-01', protocol: 'ssh',
  client_ip: '127.0.0.1', started_at: '2026-10-06T10:00:00Z', state: 'live', recording_id: 'r1',
}

function at(path: string, items: Session[] = [live]) {
  vi.spyOn(api, 'get').mockResolvedValue({ items } as never)
  render(
    <MemoryRouter initialEntries={[path]}>
      <Sessions />
    </MemoryRouter>,
  )
}

// The same page serves admins and auditors (ADR 0006): both can watch a live
// session, only an admin can end it, and recordings open in the reader's portal.
describe('Sessions', () => {
  // 2026-11-11, owner: a recording retention had deleted still had Review,
  // and only its Play said it was gone.
  it('says a recording with no file left is gone instead of offering Review', async () => {
    const ended: Session = { ...live, state: 'ended', ended_at: '2026-10-06T10:05:00Z' }
    at('/admin/sessions', [
      { ...ended, id: 's1', recording_id: 'r1', recording_state: 'purged', recording_purged: true },
      { ...ended, id: 's2', recording_id: 'r2', recording_state: 'finished' },
    ])
    const rows = (await screen.findAllByRole('row')).slice(1)
    expect(within(rows[0]).getByText('deleted')).toBeDefined()
    expect(within(rows[0]).queryByRole('link', { name: 'Review, opens in a new tab' })).toBeNull()
    expect(within(rows[1]).getByRole('link', { name: 'Review, opens in a new tab' }).getAttribute('href')).toBe('/admin/recordings/r2')
  })

  it('lets an admin watch and terminate', async () => {
    at('/admin/sessions')
    // A watch and a recording open in tabs of their own (ADR 0038), several at once.
    for (const name of ['Watch, opens in a new tab', 'Review, opens in a new tab']) {
      const link = await screen.findByRole('link', { name })
      expect([link.getAttribute('target'), link.getAttribute('rel')]).toEqual(['_blank', 'noopener noreferrer'])
    }
    expect(screen.getByRole('button', { name: 'Terminate' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'Review, opens in a new tab' }).getAttribute('href')).toBe('/admin/recordings/r1')
  })

  // Live, 2026-11-04: an administrator terminated a desktop session and
  // expected the user's portal to go back to Request. Terminate ends the
  // session, not the access, and the dialog says so, for any protocol.
  it('says that terminating keeps the access', async () => {
    at('/admin/sessions', [{ ...live, protocol: 'rdp' }])
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Terminate' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog.textContent).toContain('The session closes now; access stays.')
    expect(dialog.textContent).not.toContain('terminal')
  })

  // ADR 0047 (2026-11-09): "live" was the absence of an end reason; an
  // ended row with none read live. The state is the gateway's word.
  it('reads the state, not the absence of a reason', async () => {
    at('/admin/sessions', [{ ...live, id: 's2', state: 'ended', ended_at: '2026-10-06T10:05:00Z', recording_id: undefined }])
    expect(await screen.findByText('ended')).toBeDefined()
    expect(screen.queryByText('live')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Terminate' })).toBeNull()
  })

  it('lets an auditor watch but not terminate', async () => {
    at('/audit/sessions')
    expect((await screen.findByRole('link', { name: 'Watch, opens in a new tab' })).getAttribute('href')).toMatch(/^\/audit\/shadow\/s1/)
    expect(screen.queryByRole('button', { name: 'Terminate' })).toBeNull()
    expect(screen.getByRole('link', { name: 'Review, opens in a new tab' }).getAttribute('href')).toBe('/audit/recordings/r1')
  })

  // An application session (ADR 0034) is a browser streamed through guacd,
  // a desktop to the watcher; it is no longer the one kind without Watch.
  it('offers Watch on an application session, as a desktop', async () => {
    at('/admin/sessions', [{ ...live, id: 's2', target_name: 'wiki', protocol: 'http' }])
    const watch = await screen.findByRole('link', { name: 'Watch, opens in a new tab' })
    expect(watch.getAttribute('href')).toBe('/audit/shadow/s2?protocol=http&target=wiki')
    // the protocol reads as it does on Recordings (the live console, 2026-11-01)
    expect(screen.getByRole('cell', { name: 'HTTP' })).toBeDefined()
  })
})
