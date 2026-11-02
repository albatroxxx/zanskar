import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AdminOverview } from '../../api/types'
import { failureDetail } from '../audit/eventText'
import { Dashboard } from './Dashboard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03 live audit. Q1: Keycloak did not answer its sync for hours and
// the dashboard said nothing. Q2: "28 failures" did not say most were that.

const overview = (failing: number, audit: AdminOverview['audit_24h']): AdminOverview => ({
  sessions: { open: 0, started_24h: 0 },
  pending_requests: 0,
  targets: { active: 0, host_key_pending: 0, host_key_changed: 0, certificate_pending: 0, needing_attention: 0 },
  inventory: { hosts: 0, hosts_by_os: {}, databases: 0, databases_by_engine: {}, applications: 0 },
  autoscaling: { groups: 0, instances: 0, healthy_instances: 0 },
  audit_24h: audit,
  integrity: { audit_chain: null, recordings_lost_7d: 0, directories: { listed: 1, failing, not_run: 0, held_back: 0 }, export: { sinks: 0, behind: 0 } },
})

function mount(o: AdminOverview) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/overview') return o as never
    return new Promise(() => {}) as never
  })
  render(<MemoryRouter><Dashboard /></MemoryRouter>)
}

describe('sign-in provider health on the dashboard', () => {
  it('says plainly when a provider failed its sync, linking to the providers', async () => {
    mount(overview(1, { events: 40, failures: 28, failed_logins: 0, refused_connects: 2, top_failure: 'idp.sync', top_failure_count: 19 }))
    const alert = await screen.findByText(/A sign-in provider failed the last sync; single sign-on may be down\./)
    expect(alert.closest('.alert')?.querySelector('a')?.getAttribute('href')).toBe('/admin/identity-providers')
  })

  it('says nothing while every provider answers', async () => {
    mount(overview(0, { events: 3, failures: 0, failed_logins: 0, refused_connects: 0 }))
    await screen.findByText('Failed actions (24h)')
    expect(screen.queryByText(/failed the last sync/)).toBeNull()
  })

  it('names what most failed actions were under the count', async () => {
    mount(overview(1, { events: 40, failures: 28, failed_logins: 0, refused_connects: 2, top_failure: 'idp.sync', top_failure_count: 19 }))
    const tile = (await screen.findByText('Failed actions (24h)')).closest('a')!
    expect(tile.textContent).toContain('28')
    expect(tile.textContent).toContain('mostly provider syncs (19)')
  })
})

describe('failureDetail', () => {
  it('says all, mostly or most often, and nothing without failures', () => {
    expect(failureDetail({ failures: 2, top_failure: 'user.login', top_failure_count: 2 })).toBe('all sign-ins')
    expect(failureDetail({ failures: 28, top_failure: 'idp.sync', top_failure_count: 19 })).toBe('mostly provider syncs (19)')
    expect(failureDetail({ failures: 10, top_failure: 'cli.unlock', top_failure_count: 4 })).toBe('most often command line codes (4)')
    expect(failureDetail({ failures: 5, top_failure: 'target.probe', top_failure_count: 5 })).toBe('5 of 5: Target connection tested')
    expect(failureDetail({ failures: 0 })).toBeUndefined()
    expect(failureDetail({ failures: 3, top_failure: '', top_failure_count: 0 })).toBeUndefined()
  })
})
