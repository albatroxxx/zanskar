import { cleanup, render, screen } from '@testing-library/react'
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
  client_ip: '127.0.0.1', started_at: '2026-10-06T10:00:00Z', recording_id: 'r1',
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
  it('lets an admin watch and terminate', async () => {
    at('/admin/sessions')
    // A watch and a recording open in tabs of their own (ADR 0038), several at once.
    for (const name of ['Watch, opens in a new tab', 'play, opens in a new tab']) {
      const link = await screen.findByRole('link', { name })
      expect([link.getAttribute('target'), link.getAttribute('rel')]).toEqual(['_blank', 'noopener noreferrer'])
    }
    expect(screen.getByRole('button', { name: 'Terminate' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'play, opens in a new tab' }).getAttribute('href')).toBe('/admin/recordings/r1')
  })

  it('lets an auditor watch but not terminate', async () => {
    at('/audit/sessions')
    expect((await screen.findByRole('link', { name: 'Watch, opens in a new tab' })).getAttribute('href')).toMatch(/^\/audit\/shadow\/s1/)
    expect(screen.queryByRole('button', { name: 'Terminate' })).toBeNull()
    expect(screen.getByRole('link', { name: 'play, opens in a new tab' }).getAttribute('href')).toBe('/audit/recordings/r1')
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
