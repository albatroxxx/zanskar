import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AuditOverview, AuditVerify } from '../../api/types'
import { Dashboard } from './Dashboard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const overview: AuditOverview = {
  sessions: { open: 1, started_24h: 6 },
  events_24h: { events: 90, failures: 5, failed_logins: 3, refused_connects: 2 },
  reviews_24h: { recording_views: 4, recording_downloads: 1 },
}

const intact: AuditVerify = { intact: true, checked: 90, last_id: 90, last_hash: 'aa', anchors_checked: 2 }

describe('the auditor dashboard', () => {
  it('shows the day in counts, each linking into the audit portal', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/audit/overview') return overview as never
      throw new Error('unexpected ' + path)
    })
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    )

    const failures = (await screen.findByText('Failures (24h)')).closest('a')
    expect(failures?.getAttribute('href')).toBe('/audit/events?outcome=failure&range=24h&routine=1')
    expect(failures?.textContent).toContain('5')
    // 2026-10-30: every number opens the list it counted. Recordings played
    // and downloaded are counts of audit events, so they open those events.
    const href = (label: string) => screen.getByText(label).closest('a')?.getAttribute('href')
    expect(href('Open sessions')).toBe('/audit/sessions?open=1')
    expect(href('Sessions (24h)')).toBe('/audit/sessions?range=24h')
    expect(href('Failed sign-ins (24h)')).toBe('/audit/events?action=user.login&outcome=failure&range=24h&routine=1')
    expect(href('Refused connections (24h)')).toBe('/audit/events?action=session.connect&outcome=failure&range=24h&routine=1')
    expect(href('Audit events (24h)')).toBe('/audit/events?range=24h&routine=1')
    expect(href('Recordings played (24h)')).toBe('/audit/events?action=recording.view&outcome=success&range=24h&routine=1')
    expect(href('Recordings downloaded (24h)')).toBe('/audit/events?action=recording.download&outcome=success&range=24h&routine=1')
  })

  it('checks the chain only when asked, then shows the verdict', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/audit/overview') return overview as never
      if (path === '/audit/verify') return intact as never
      throw new Error('unexpected ' + path)
    })
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    )

    await screen.findByText('Failures (24h)')
    expect(get).not.toHaveBeenCalledWith('/audit/verify')

    await userEvent.setup().click(screen.getByRole('button', { name: 'Check the chain' }))
    expect(await screen.findByText(/chain intact · 90 events/)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Check again' })).toBeDefined()
  })
})
