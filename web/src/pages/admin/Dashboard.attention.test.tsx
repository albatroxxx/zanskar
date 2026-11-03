import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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
// in Needs attention (UI/UX, idea 1); a recordings disk that fills offers
// the move to the bucket where it warns (idea 8).

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
  it('holds failed actions and failing sign-in providers, which Activity no longer does', async () => {
    open(overview(2), null)
    await screen.findByText('Failed actions (24h)')
    const attention = within(section('Needs attention'))
    expect(attention.getByText('Failed actions (24h)')).toBeDefined()
    const providers = attention.getByText('Sign-in providers failing').closest('a')!
    expect(providers.getAttribute('href')).toBe('/admin/identity-providers')
    expect(providers.textContent).toContain('2')
    expect(providers.className).toContain('danger')
    expect(within(section('Activity')).queryByText('Failed actions (24h)')).toBeNull()
  })

  it('keeps the providers tile quiet at zero, and keeps it with no provider so the row stays whole', async () => {
    open(overview(0), null)
    const tile = (await screen.findByText('Sign-in providers failing')).closest('a')!
    expect(tile.className).not.toContain('danger')
    cleanup()
    vi.restoreAllMocks()
    open(overview(0, 0), null)
    await screen.findByText('Failed actions (24h)')
    expect(within(section('Needs attention')).getByText('Sign-in providers failing')).toBeDefined()
  })

  // 2026-11-03: six tiles under Needs attention and three under Activity
  // left ragged rows; every section holds four, one row on a wide window.
  it('puts four tiles in every section, the 24h counts under Activity', async () => {
    for (const providers of [1, 0]) {
      cleanup()
      vi.restoreAllMocks()
      open(overview(0, providers), null)
      await screen.findByText('Failed actions (24h)')
      for (const name of ['Inventory', 'Needs attention', 'Activity', 'Security posture']) {
        expect(section(name).querySelectorAll('.stat-tile').length, name).toBe(4)
      }
      const activity = within(section('Activity'))
      expect(activity.getByText('Failed sign-ins (24h)')).toBeDefined()
      expect(activity.getByText('Refused connections (24h)')).toBeDefined()
      expect(screen.queryByText('Grants active')).toBeNull()
    }
  })
})

describe('a recordings disk that fills', () => {
  it('moves the local recordings to the bucket in one confirmed step', async () => {
    const { post } = open(overview(0), { what: 'database & recordings', usedGB: 85, freeGB: 15 })
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Move 3 local recordings to the bucket' }))
    expect(screen.getByText(/copied to s3:\/\/recs, verified and removed locally/)).toBeDefined()
    expect(post).not.toHaveBeenCalled()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Move' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/storage/move'))
    expect(await screen.findByText(/Moving local recordings to the bucket/)).toBeDefined()
    expect(screen.queryByRole('button', { name: /Move 3/ })).toBeNull()
  })

  it('points to Recording storage when no bucket is set up', async () => {
    open(overview(0), { what: 'recordings', usedGB: 81, freeGB: 19 }, storage({ source: 'local', active: undefined, counts: { local: 40 } }))
    const link = await screen.findByRole('link', { name: 'Recording storage' })
    expect(link.getAttribute('href')).toBe('/admin/settings#settings-recording-storage')
    expect(screen.getByText(/Record to an S3 bucket instead/)).toBeDefined()
  })

  it('says a move is under way rather than offering another', async () => {
    open(overview(0), { what: 'recordings', usedGB: 90, freeGB: 10 }, storage({ move: { running: true, moved: 1, failed: 0, total: 3 } }))
    expect(await screen.findByText(/Moving local recordings to the bucket/)).toBeDefined()
    expect(screen.queryByRole('button', { name: /local recording/ })).toBeNull()
  })

  it('offers nothing with every recording in the bucket already', async () => {
    const { get } = open(overview(0), { what: 'recordings', usedGB: 90, freeGB: 10 }, storage({ counts: { recs: 12 } }))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/admin/storage'))
    await screen.findByRole('meter', { name: 'System disk' })
    expect(screen.queryByText(/local recording/)).toBeNull()
    expect(screen.queryByText(/Record to an S3 bucket/)).toBeNull()
  })

  it('reads nothing below 80% or on a disk without recordings', async () => {
    const below = open(overview(0), { what: 'database & recordings', usedGB: 79, freeGB: 21 })
    await screen.findByRole('meter', { name: 'System disk' })
    expect(below.get).not.toHaveBeenCalledWith('/admin/storage')
    cleanup()
    vi.restoreAllMocks()
    const db = open(overview(0), { what: 'database', usedGB: 90, freeGB: 10 })
    await screen.findByRole('meter', { name: 'System disk' })
    expect(db.get).not.toHaveBeenCalledWith('/admin/storage')
  })

  it('stays quiet when the storage status cannot be read', async () => {
    const { get } = open(overview(0), { what: 'recordings', usedGB: 90, freeGB: 10 }, new Error('forbidden'))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/admin/storage'))
    await screen.findByRole('meter', { name: 'System disk' })
    expect(screen.queryByText(/bucket/)).toBeNull()
  })
})
