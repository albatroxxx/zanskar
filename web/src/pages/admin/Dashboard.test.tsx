import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { setDisplayZone } from '../../api/format'
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
  targets: { active: 5, host_key_pending: 1, host_key_changed: 1, certificate_pending: 1, needing_attention: 2 },
  inventory: { hosts: 3, hosts_by_os: { linux: 2, windows: 1 }, databases: 2, databases_by_engine: { postgres: 1, mysql: 1 }, applications: 4 },
  autoscaling: { groups: 1, instances: 4, healthy_instances: 3 },
  audit_24h: { events: 41, failures: 4, failed_logins: 2, refused_connects: 1 },
  posture: { standing_no_mfa: { grants: 3, policies: 2 }, admins: 2, dormant: 4, not_enrolled: 1 },
  integrity: { audit_chain: null, recordings_lost_7d: 1, directories: { listed: 1, failing: 0, not_run: 0, held_back: 0 }, export: { sinks: 0, behind: 0 } },
  in_flight: { active: 3, ending_soon: 1, oldest_pending_seconds: 7500 },
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
  cpu: { percent: 37.4, window_seconds: 10 },
  load: { one: 0.42, five: 0.2, fifteen: 0.1 },
  memory: { total_bytes: 8 * 1024 ** 3, available_bytes: 6 * 1024 ** 3 },
  disks: [
    { what: 'database & recordings', path: '/var/lib/zanskar', system: true, total_bytes: 100 * 1024 ** 3, free_bytes: 4 * 1024 ** 3 },
  ],
  database_sessions: 1,
  guacd: { address: '127.0.0.1:4822', reachable: false },
  cpus: 8,
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

    // Each host once, however many decisions it waits on (three reasons, two
    // hosts), opening the hosts that wait.
    const hosts = screen.getByText('Hosts needing attention').closest('a')
    expect(hosts?.getAttribute('href')).toBe('/admin/hosts?attention=1')
    expect(hosts?.textContent).toContain('2')

    // 2026-10-30: every number opens the list it counted, not the whole page.
    const href = (label: string) => screen.getByText(label).closest('a')?.getAttribute('href')
    expect(href('Failed sign-ins (24h)')).toBe('/admin/events?action=user.login&outcome=failure&range=24h&routine=1')
    expect(href('Refused connections (24h)')).toBe('/admin/events?action=session.connect&outcome=failure&range=24h&routine=1')
    expect(href('Failures (24h)')).toBe('/admin/events?outcome=failure&range=24h&routine=1')
    // The day's events are a line in the integrity row since 2026-10-31.
    expect(href('Audit log')).toBe('/admin/events?range=24h&routine=1')
    expect(href('Open sessions')).toBe('/admin/sessions?open=1')
    expect(href('Sessions (24h)')).toBe('/admin/sessions?range=24h')

    // The inventory row: totals with their mix, each linking to its page.
    const hostsTile = screen.getByText('2 Linux · 1 Windows').closest('a')
    expect(hostsTile?.getAttribute('href')).toBe('/admin/hosts?status=active')
    expect(hostsTile?.textContent).toContain('3')
    expect(screen.getByText('1 PostgreSQL · 1 MySQL').closest('a')?.getAttribute('href')).toBe('/admin/databases?status=active')
    const apps = screen.getByText('Applications').closest('a')
    expect(apps?.getAttribute('href')).toBe('/admin/applications?status=active')
    expect(apps?.textContent).toContain('4')
    expect(screen.getByText('3 of 4 instances healthy').closest('a')?.getAttribute('href')).toBe('/admin/autoscaling')
    expect(screen.getByText(/Zanskar 1\.4\.0, up 2 hours under systemd/)).toBeDefined()

    // The host gauges: each ratio is a meter with its words beside it, the
    // disk at 4 GB of 100 GB free reads as danger, and the facts that are
    // not ratios stay in words.
    const cpu = screen.getByRole('meter', { name: 'CPU (8 cores)' })
    expect(cpu.getAttribute('aria-valuenow')).toBe('37')
    expect(cpu.parentElement?.textContent).toContain('37% busy')
    expect(cpu.parentElement?.textContent).toContain('load 0.10 over 15 min')
    const memory = screen.getByRole('meter', { name: 'Memory' })
    expect(memory.getAttribute('aria-valuenow')).toBe('25')
    // 2026-10-30: every gauge leads with its percentage, as CPU did.
    expect(memory.parentElement?.textContent).toContain('25% used · 2.0 GB of 8.0 GB')
    const disk = screen.getByRole('meter', { name: 'System disk' })
    expect(disk.getAttribute('aria-valuenow')).toBe('96')
    expect(disk.className).toContain('danger')
    expect(disk.parentElement?.textContent).toContain('96% used · 4.0 GB free of 100.0 GB')
    expect(disk.parentElement?.querySelector('.gauge-pct')?.className).toContain('danger')
    expect(screen.getByRole('button', { name: /Low space: 4\.0 GB free/ })).toBeDefined()
    expect(screen.getByText(/1 database session container/)).toBeDefined()
    expect(screen.getByText(/unreachable at 127\.0\.0\.1:4822/)).toBeDefined()
  })

  // 2026-10-31: the dashboard says what weakens access, each number a link.
  it('shows the security posture, each tile opening its page', async () => {
    serve()
    at('/')
    const tile = async (label: string) => (await screen.findByText(label)).closest('a') as HTMLAnchorElement
    const standing = await tile('Standing access without MFA')
    expect(standing.getAttribute('href')).toBe('/admin/policies')
    expect(standing.textContent).toContain('3')
    expect(standing.textContent).toContain('in 2 policies')
    expect(standing.className).toContain('danger')
    expect((await tile('No authenticator yet')).textContent).toContain('1')
    expect((await tile('Dormant (90 days)')).textContent).toContain('4')
    const admins = await tile('Administrators')
    expect(admins.textContent).toContain('2')
    expect(admins.className).not.toContain('warn')
    // The section sits between what needs a decision and what is happening.
    const sections = [...document.querySelectorAll('h2.stat-section')].map((h) => h.textContent)
    expect(sections.indexOf('Security posture')).toBe(sections.indexOf('Needs attention') + 1)
    expect(sections.indexOf('Activity')).toBe(sections.indexOf('Security posture') + 1)
  })

  // 2026-10-31: access in flight, on the tiles it belongs with.
  it('says how long the oldest request has waited and which grants end soon', async () => {
    serve()
    at('/')
    const approvals = (await screen.findByText('Pending approvals')).closest('a') as HTMLAnchorElement
    expect(approvals.textContent).toContain('oldest waiting 2 hours')
    const grants = (await screen.findByText('Grants active')).closest('a') as HTMLAnchorElement
    expect(grants.getAttribute('href')).toBe('/admin/approvals')
    expect(grants.textContent).toContain('3')
    expect(grants.textContent).toContain('1 end within the hour')
    expect(screen.queryByText('Audit events (24h)')).toBeNull()
  })

  it('shows the integrity row as status lines that open their pages', async () => {
    serve()
    at('/')
    const line = async (label: string) => (await screen.findByText(label)).closest('a') as HTMLAnchorElement
    expect((await line('Audit chain')).textContent).toContain('Not checked yet')
    const rec = await line('Recordings')
    expect(rec.className).toContain('danger')
    expect(rec.getAttribute('href')).toBe('/admin/events?action=recording.lost&outcome=failure&range=7d')
    expect((await line('Identity providers')).textContent).toContain('In sync')
    expect((await line('SIEM export')).textContent).toContain('Not configured')
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

    expect(await screen.findByText(/The environment file changed/)).toBeDefined()
    expect(screen.getByText(/days left/)).toBeDefined()
  })

  it('shows no certificate sentence in proxy mode', async () => {
    serve({ '/admin/tls': { mode: 'proxy' } })
    at('/')

    expect(await screen.findByText(/Zanskar 1\.4\.0/)).toBeDefined()
    expect(screen.queryByText(/TLS certificate/)).toBeNull()
  })

  // A host that cannot say how busy its processors are (no /proc/stat)
  // still shows the load average, as before.
  // df's Use% counts the blocks kept for root as neither used nor free; the
  // console's percentage must be the one a terminal shows (2026-10-30).
  it('works out a disk\'s percentage the way df does', async () => {
    serve({ '/admin/system/metrics': { ...metrics, disks: [{ what: 'database', path: '/', system: true, total_bytes: 100 * 1024 ** 3, free_bytes: 10 * 1024 ** 3, used_bytes: 80 * 1024 ** 3 }] } })
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    )
    const disk = await screen.findByRole('meter', { name: 'System disk' })
    // 100 GB with 10 kept for root: df says 80 / (80 + 10) = 88.9%, rounded
    // up to 89%; 1 - free/total would have said 90%.
    expect(disk.parentElement?.textContent).toContain('89% used')
    expect(disk.getAttribute('aria-valuenow')).toBe('89')
  })

  it('shows the gateway\'s time in the console\'s zone, from the gateway\'s clock', async () => {
    setDisplayZone('Asia/Kolkata')
    const gatewayNow = Date.now() + 3 * 3600_000 // the browser's clock runs three hours behind
    serve({ '/admin/system/status': { ...status, now: new Date(gatewayNow).toISOString() } })
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    )
    const clock = await screen.findByRole('region', { name: 'Gateway time' })
    await waitFor(() => {
      const shown = clock.querySelector('time')!.getAttribute('datetime')!
      expect(Math.abs(Date.parse(shown) - gatewayNow)).toBeLessThan(5000)
    })
    expect(clock.textContent).toContain('Asia/Kolkata · UTC+05:30')
    setDisplayZone(undefined)
  })

  it('falls back to the load average without a CPU reading', async () => {
    serve({ '/admin/system/metrics': { ...metrics, cpu: undefined } })
    at('/')
    const load = await screen.findByRole('meter', { name: 'Load (8 cores)' })
    expect(load.getAttribute('aria-valuenow')).toBe('5')
    expect(screen.queryByRole('meter', { name: 'CPU (8 cores)' })).toBeNull()
  })

  // The gateway card used to read its numbers once, so the CPU stood where
  // the page had found it until a reload.
  it('reads the host numbers again every ten seconds while open', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    try {
      const get = serve()
      const view = at('/')
      expect(await screen.findByRole('meter', { name: 'CPU (8 cores)' })).toBeDefined()
      const before = get.mock.calls.filter(([p]) => p === '/admin/system/metrics').length
      await act(async () => { vi.advanceTimersByTime(10_000) })
      await act(async () => { vi.advanceTimersByTime(10_000) })
      const after = get.mock.calls.filter(([p]) => p === '/admin/system/metrics').length
      expect(after).toBe(before + 2)
      view.unmount()
      await act(async () => { vi.advanceTimersByTime(30_000) })
      expect(get.mock.calls.filter(([p]) => p === '/admin/system/metrics').length).toBe(after)
    } finally {
      vi.useRealTimers()
    }
  })
})
