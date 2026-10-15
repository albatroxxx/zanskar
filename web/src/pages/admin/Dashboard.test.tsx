import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { AdminOverview, SystemMetrics, SystemStatus, TLSStatus } from '../../api/types'
import { Dashboard } from './Dashboard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const overview: AdminOverview = {
  sessions: { open: 2, started_24h: 7 },
  pending_requests: 3,
  targets: { active: 5, host_key_pending: 1, host_key_changed: 1, certificate_pending: 0 },
  inventory: { hosts: 3, hosts_by_os: { linux: 2, windows: 1 }, databases: 2, databases_by_engine: { postgres: 1, mysql: 1 } },
  autoscaling: { groups: 1, instances: 4, healthy_instances: 3 },
  audit_24h: { events: 41, failures: 4, failed_logins: 2, refused_connects: 1 },
}

const status: SystemStatus = {
  version: '1.4.0',
  started_at: '2026-10-14T08:00:00Z',
  uptime_seconds: 7200,
  supervisor: 'systemd',
  live_sessions: 2,
  env_file: { state: 'unchanged', changed: [], checked_at: '2026-10-14T10:00:00Z' },
  restart_required: false,
  draining: false,
}

const metrics: SystemMetrics = {
  load: { one: 0.42, five: 0.2, fifteen: 0.1 },
  memory: { total_bytes: 8 * 1024 ** 3, available_bytes: 6 * 1024 ** 3 },
  disks: [
    { what: 'database & recordings', path: '/var/lib/zanskar', total_bytes: 100 * 1024 ** 3, free_bytes: 4 * 1024 ** 3 },
  ],
  database_sessions: 1,
  guacd: { address: '127.0.0.1:4822', reachable: false },
}

const tls: TLSStatus = {
  mode: 'managed',
  active: {
    source: 'generated',
    subject: 'CN=zanskar',
    issuer: 'CN=zanskar',
    hosts: ['gw.example.com'],
    not_before: '2026-01-01T00:00:00Z',
    not_after: '2028-01-01T00:00:00Z',
    fingerprint: 'ab',
    self_signed: true,
  },
}

const serve = (over: Partial<Record<string, unknown>> = {}) =>
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path in over) {
      const v = over[path]
      if (v instanceof Error) throw v
      return v as never
    }
    if (path === '/admin/overview') return overview as never
    if (path === '/admin/system/status') return status as never
    if (path === '/admin/tls') return tls as never
    if (path === '/admin/system/metrics') return metrics as never
    throw new Error('unexpected ' + path)
  })

const at = (route: string) =>
  render(
    <MemoryRouter>
      <Dashboard key={route} />
    </MemoryRouter>,
  )

describe('the admin dashboard', () => {
  it('shows each count beside words that say what it is, linking to its page', async () => {
    serve()
    at('/')

    expect(await screen.findByText('Pending approvals')).toBeDefined()
    const approvals = screen.getByText('Pending approvals').closest('a')
    expect(approvals?.getAttribute('href')).toBe('/admin/approvals')
    expect(approvals?.textContent).toContain('3')

    // The two host-key states and the pending certificate fold into one tile.
    const hosts = screen.getByText('Hosts needing attention').closest('a')
    expect(hosts?.getAttribute('href')).toBe('/admin/hosts')
    expect(hosts?.textContent).toContain('2')

    expect(screen.getByText('Open sessions').closest('a')?.getAttribute('href')).toBe('/admin/sessions')

    // The inventory row: totals with their mix, each linking to its page.
    const hostsTile = screen.getByText('2 Linux · 1 Windows').closest('a')
    expect(hostsTile?.getAttribute('href')).toBe('/admin/hosts')
    expect(hostsTile?.textContent).toContain('3')
    expect(screen.getByText('1 PostgreSQL · 1 MySQL').closest('a')?.getAttribute('href')).toBe('/admin/databases')
    expect(screen.getByText('3 of 4 instances healthy').closest('a')?.getAttribute('href')).toBe('/admin/autoscaling')
    expect(screen.getByText(/Zanskar 1\.4\.0, up 2 hours under systemd/)).toBeDefined()

    // The host facts: numbers in one line, a volume line with a tone only
    // when the free space asks for action (4 GB of 100 GB left → danger).
    expect(screen.getByText(/load 0\.42/)).toBeDefined()
    expect(screen.getByText(/1 database session container/)).toBeDefined()
    expect(screen.getByText(/unreachable at 127\.0\.0\.1:4822/)).toBeDefined()
    expect(screen.getByText(/Database & recordings volume: 4\.0 GB free of 100\.0 GB/)).toBeDefined()
    expect(screen.getByText('low space')).toBeDefined()
  })

  it('says the overview failed rather than showing a quiet system', async () => {
    serve({ '/admin/overview': new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'r1' }, '500') })
    at('/')

    expect(await screen.findByText(/dashboard could not be fully loaded: database is locked/)).toBeDefined()
    // The tiles stay as placeholders, never as zeros.
    expect(screen.queryByText('0')).toBeNull()
  })

  it('warns when the TLS certificate is near expiry and when a restart is required', async () => {
    serve({
      '/admin/system/status': { ...status, restart_required: true },
      '/admin/tls': { ...tls, active: { ...tls.active, not_after: new Date(Date.now() + 5 * 86400000).toISOString() } },
    })
    at('/')

    expect(await screen.findByText(/a restart applies it/)).toBeDefined()
    expect(screen.getByText(/days left/)).toBeDefined()
  })

  it('shows no certificate sentence in proxy mode', async () => {
    serve({ '/admin/tls': { mode: 'proxy' } })
    at('/')

    expect(await screen.findByText(/Zanskar 1\.4\.0/)).toBeDefined()
    expect(screen.queryByText(/TLS certificate/)).toBeNull()
  })
})
