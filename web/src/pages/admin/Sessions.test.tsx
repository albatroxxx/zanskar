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

function at(path: string) {
  vi.spyOn(api, 'get').mockResolvedValue({ items: [live] } as never)
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
    expect(await screen.findByRole('link', { name: 'Watch' })).toBeDefined()
    expect(screen.getByRole('button', { name: 'Terminate' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'play' }).getAttribute('href')).toBe('/admin/recordings/r1')
  })

  it('lets an auditor watch but not terminate', async () => {
    at('/audit/sessions')
    expect((await screen.findByRole('link', { name: 'Watch' })).getAttribute('href')).toMatch(/^\/audit\/shadow\/s1/)
    expect(screen.queryByRole('button', { name: 'Terminate' })).toBeNull()
    expect(screen.getByRole('link', { name: 'play' }).getAttribute('href')).toBe('/audit/recordings/r1')
  })
})
