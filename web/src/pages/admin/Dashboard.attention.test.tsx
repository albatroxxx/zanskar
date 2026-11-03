import { cleanup, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AdminOverview, StorageStatus } from '../../api/types'
import { Dashboard } from './Dashboard'

beforeEach(() => localStorage.clear())
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, after 1.15.0: what 1.15.0 left of the live audit. Failed
// actions and a failing sign-in provider are things to look at, so they sit
// in Needs attention (UI/UX, idea 1). A recordings disk that fills warns;
// the move to the bucket is on Settings, not here.

const gb = 1024 ** 3

const overview = (failing: number, listed = 1): AdminOverview => ({
  sessions: { open: 0, started_24h: 0 },
  pending_requests: 0,
  targets: { active: 0, host_key_pending: 0, host_key_changed: 0, certificate_pending: 0, needing_attention: 0 },
  inventory: { hosts: 0, hosts_by_os: {}, databases: 0, databases_by_engine: {}, applications: 0 },
  autoscaling: { groups: 0, instances: 0, healthy_instances: 0 },
  audit_24h: { events: 30, failures: 28, failed_logins: 0, refused_connects: 0 },
  integrity: { audit_chain: null, recordings_lost_7d: 0, directories: { listed, failing, not_run: 0, held_back: 0 }, export: { sinks: 0, behind: 0 } },
})

const storage = (over: Partial<StorageStatus> = {}): StorageStatus => ({
  source: 'console',
  active: { bucket: 'recs', prefix: 'recordings/', region: 'eu-west-2', endpoint: '', kms_key_id: '', auth: 'role', access_key_id: '', secret_access_key: '' },
  counts: { local: 3, recs: 9 },
  move: { running: false, moved: 0, failed: 0, total: 0 },
  ...over,
})

/** open mounts the dashboard with an overview, a disk and a storage status. */
function open(o: AdminOverview, disk: { what: string; usedGB: number; freeGB: number } | null, st: StorageStatus | Error = storage()) {
  const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/overview') return o as never
    if (path === '/admin/system/status') {
      return { version: '1.15.0', started_at: '', uptime_seconds: 60, supervisor: 'systemd', live_sessions: 0, env_file: { state: 'unchanged', changed: [], checked_at: '' }, restart_required: false, draining: false } as never
    }
    if (path === '/admin/storage') {
      if (st instanceof Error) throw st
      return st as never
    }
    if (path === '/admin/system/metrics' && disk) {
      return {
        cpu: { percent: 1, window_seconds: 10 }, cpus: 2, database_sessions: 0,
        disks: [{ what: disk.what, path: '/var/lib/zanskar', system: true, total_bytes: (disk.usedGB + disk.freeGB) * gb, free_bytes: disk.freeGB * gb, used_bytes: disk.usedGB * gb }],
      } as never
    }
    return new Promise(() => {}) as never
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
  render(<MemoryRouter><Dashboard /></MemoryRouter>)
  return { get, post }
}

const section = (name: string) => screen.getByRole('heading', { name }).closest('section') as HTMLElement

describe('Needs attention', () => {
  it('holds the failed actions and the failed sign-ins; Activity holds the live grants and the refused connections', async () => {
    open(overview(2), null)
    await screen.findByText('Failed actions (24h)')
    const attention = within(section('Needs attention'))
    expect(attention.getByText('Failed actions (24h)')).toBeDefined()
    expect(attention.getByText('Failed sign-ins (24h)')).toBeDefined()
    const activity = within(section('Activity'))
    expect(activity.getByText('Grants active')).toBeDefined()
    expect(activity.getByText('Refused connections (24h)')).toBeDefined()
    expect(activity.queryByText('Failed actions (24h)')).toBeNull()
  })

  // 2026-11-03, later: the owner took the providers tile out ("an
  // unnecessary attempt to make four boxes"); the notice that a provider
  // failed its sync stays, above the tiles.
  it('has no tile for failing providers, only the notice', async () => {
    open(overview(2), null)
    await screen.findByText('Failed actions (24h)')
    expect(screen.queryByText('Sign-in providers failing')).toBeNull()
    expect(screen.getByText(/failed the last sync/)).toBeDefined()
  })

  // Four tiles in every section, so a row is four or two, never ragged.
  it('puts four tiles in every section', async () => {
    for (const providers of [1, 0]) {
      cleanup()
      vi.restoreAllMocks()
      open(overview(0, providers), null)
      await screen.findByText('Failed actions (24h)')
      for (const name of ['Inventory', 'Needs attention', 'Activity', 'Security posture']) {
        expect(section(name).querySelectorAll('.stat-tile').length, name).toBe(4)
      }
    }
  })
})

describe('a recordings disk that fills', () => {
  // 2026-11-03: the owner wants the dashboard clean. The disk still warns;
  // setting up a bucket and moving recordings to it stay on Settings,
  // Recording storage, and the dashboard neither offers them nor reads them.
  it('warns, and offers no bucket and no move', async () => {
    for (const st of [storage(), storage({ source: 'local', active: undefined, counts: { local: 40 } })]) {
      cleanup()
      vi.restoreAllMocks()
      const { get } = open(overview(0), { what: 'database & recordings', usedGB: 90, freeGB: 10 }, st)
      // The bar's colour says it (2026-11-03: no icon beside the reading).
      const meter = await screen.findByRole('meter', { name: 'System disk' })
      expect(meter.className).toContain('warn')
      expect(screen.queryByRole('button', { name: /Low space/ })).toBeNull()
      expect(screen.queryByText(/bucket|S3/)).toBeNull()
      expect(screen.queryByRole('link', { name: 'Recording storage' })).toBeNull()
      expect(screen.queryByRole('button', { name: /recording/i })).toBeNull()
      expect(get).not.toHaveBeenCalledWith('/admin/storage')
    }
  })
})
