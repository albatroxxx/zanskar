import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AdminOverview } from '../../api/types'
import { Dashboard } from './Dashboard'
import { dismiss, dismissal, REMIND_MS, shown } from './dismissals'

beforeEach(() => localStorage.clear())
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, the live 1.15.0 console: the notice that a sign-in provider
// failed its sync came back each time the dashboard was opened again, though
// it had been closed. Closed, it stays closed while the outage lasts, is
// forgotten when the providers recover, and is said again when more fail or
// after a day.

const NOTICE = /failed the last sync; single sign-on may be down/
const KEY = 'providers-failing'

const overview = (failing: number): AdminOverview => ({
  sessions: { open: 0, started_24h: 0 },
  pending_requests: 0,
  targets: { active: 0, host_key_pending: 0, host_key_changed: 0, certificate_pending: 0, needing_attention: 0 },
  inventory: { hosts: 0, hosts_by_os: {}, databases: 0, databases_by_engine: {}, applications: 0, clusters: 0, clusters_by_platform: {} },
  autoscaling: { groups: 0, instances: 0, healthy_instances: 0 },
  audit_24h: { events: 0, failures: 0, failed_logins: 0, refused_connects: 0 },
  integrity: { audit_chain: null, recordings_lost_7d: 0, directories: { listed: 2, failing, not_run: 0, held_back: 0 }, export: { sinks: 0, behind: 0 } },
})

/** open mounts the dashboard as navigating to it does, with failing providers. */
function open(failing: number) {
  vi.restoreAllMocks()
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/overview') return overview(failing) as never
    return new Promise(() => {}) as never
  })
  return render(<MemoryRouter><Dashboard /></MemoryRouter>)
}

/** loaded waits for the overview to be on the page. */
const loaded = () => screen.findByText('Failed actions (24h)')

/** closeOf finds the close button of the notice holding text. */
function closeOf(text: HTMLElement): HTMLElement {
  return text.closest('.alert')!.querySelector('button[aria-label="Dismiss"]') as HTMLElement
}

describe('the provider notice, closed', () => {
  it('stays closed when the dashboard is opened again', async () => {
    const first = open(1)
    await userEvent.setup().click(closeOf(await screen.findByText(NOTICE)))
    expect(screen.queryByText(NOTICE)).toBeNull()
    first.unmount()
    open(1)
    await loaded()
    expect(screen.queryByText(NOTICE)).toBeNull()
  })

  it('shows again when more providers fail than when it was closed', async () => {
    dismiss(KEY, { at: Date.now(), count: 1 })
    open(2)
    expect(await screen.findByText(/2 sign-in providers failed the last sync/)).toBeDefined()
  })

  it('stays closed when fewer fail than when it was closed', async () => {
    dismiss(KEY, { at: Date.now(), count: 2 })
    open(1)
    await loaded()
    expect(screen.queryByText(NOTICE)).toBeNull()
  })

  it('is said again after a day of the same outage', async () => {
    dismiss(KEY, { at: Date.now() - REMIND_MS - 1000, count: 1 })
    open(1)
    expect(await screen.findByText(NOTICE)).toBeDefined()
  })

  it('is forgotten when the providers recover, so the next outage shows', async () => {
    dismiss(KEY, { at: Date.now(), count: 1 })
    const healthy = open(0)
    await loaded()
    await waitFor(() => expect(dismissal(KEY)).toBeNull())
    healthy.unmount()
    open(1)
    expect(await screen.findByText(NOTICE)).toBeDefined()
  })

  it('shows when what is kept cannot be read', async () => {
    for (const kept of ['', 'x', '123', '/1', '123/', '123/0', '-5/1', '1.5/1', 'Infinity/1']) {
      localStorage.setItem('zanskar.dismissed.' + KEY, kept)
      expect(dismissal(KEY), kept).toBeNull()
    }
    open(1)
    expect(await screen.findByText(NOTICE)).toBeDefined()
  })
})

describe('shown', () => {
  const now = 1_000_000_000_000
  it('shows a notice never closed', () => expect(shown(null, 1, now)).toBe(true))
  it('hides it within the day at the same or a lower count', () => {
    expect(shown({ at: now - 60_000, count: 2 }, 2, now)).toBe(false)
    expect(shown({ at: now - 60_000, count: 2 }, 1, now)).toBe(false)
  })
  it('shows it at a higher count', () => expect(shown({ at: now - 60_000, count: 1 }, 2, now)).toBe(true))
  it('shows it a day after it was closed', () => expect(shown({ at: now - REMIND_MS, count: 1 }, 1, now)).toBe(true))
  it('round-trips what dismiss keeps', () => {
    dismiss(KEY, { at: now, count: 3 })
    expect(dismissal(KEY)).toEqual({ at: now, count: 3 })
  })
})
