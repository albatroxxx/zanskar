import { describe, expect, it } from 'vitest'
import type { SystemStatus, UpdateStatus } from '../api/types'
import { deadlineFor, doneTitle, initialProgress, observe, poweroffQuietMs, progressWatch, stepLabel, type HostAction, type Progress, type Start } from './hostAction'

const t0 = 1_000_000
const status = (over: Partial<SystemStatus> = {}): SystemStatus =>
  ({ version: '1.8.0', started_at: '2026-10-30T10:00:00Z', uptime_seconds: 60, supervisor: 'systemd', live_sessions: 0, restart_required: false, draining: true, env_file: { state: 'off' }, ...over }) as SystemStatus
const start = (action: HostAction, over: Partial<Start> = {}): Start => ({ action, target: action === 'update' ? '1.9.0' : undefined, startedAt: '2026-10-30T10:00:00Z', at: t0, deadline: deadlineFor(action, 0, t0), ...over })
const installer = (state: 'running' | 'done' | 'failed', message: string, at = '2026-10-30T10:05:00Z', version = '1.9.0'): UpdateStatus =>
  ({ current: '1.8.0', newer: true, enabled: true, installable: true, install: { state, version, message, at } }) as UpdateStatus

/** run feeds observations in order and returns every progress seen. */
function run(s: Start, obs: Parameters<typeof observe>[2][]): Progress[] {
  const out: Progress[] = []
  let p = initialProgress
  for (const o of obs) {
    p = observe(s, p, o)
    out.push(p)
  }
  return out
}

// 2026-10-30: the dialogs said "Installing…" and stopped; the progress view
// follows the action to its end and judges it by what the gateway says.
describe('host action progress', () => {
  it('follows an update through the drain, the installer, the restart, and back on the new version', () => {
    const s = start('update', { installBefore: '2026-10-29T09:00:00Z' })
    const seen = run(s, [
      { at: t0 + 2000, status: status({ live_sessions: 2, drain: { requested_at: '', requested_by: '', deadline: '2026-10-30T10:15:00Z', wait_minutes: 15 } }) },
      { at: t0 + 4000, status: status(), update: installer('running', 'verifying the signature') },
      { at: t0 + 6000, status: status(), update: installer('done', 'installed 1.9.0') },
      { at: t0 + 8000, error: 'offline' },
      { at: t0 + 10000, status: status({ started_at: '2026-10-30T10:06:00Z', version: '1.9.0', draining: false }) },
    ])
    expect(seen.map((p) => [p.state, p.step])).toEqual([
      ['running', 'drain'],
      ['running', 'install'],
      ['running', 'restart'],
      ['running', 'restart'],
      ['done', 'back'],
    ])
    expect(seen[0].live).toBe(2)
    expect(seen[1].message).toBe('verifying the signature')
  })

  it('says why an update failed, from the installer', () => {
    const s = start('update', { installBefore: '2026-10-29T09:00:00Z' })
    const [p] = run(s, [{ at: t0 + 2000, status: status(), update: installer('failed', 'the release signature did not verify') }])
    expect(p).toMatchObject({ state: 'failed', step: 'install', message: 'the release signature did not verify' })
  })

  it('does not read an earlier attempt\'s report as this one', () => {
    const s = start('update', { installBefore: '2026-10-29T09:00:00Z' })
    const [p] = run(s, [{ at: t0 + 2000, status: status(), update: installer('failed', 'old failure', '2026-10-29T09:00:00Z') }])
    expect(p.state).toBe('running')
  })

  it('fails an update that comes back on the old version', () => {
    const [p] = run(start('update'), [{ at: t0 + 2000, status: status({ started_at: 'later', version: '1.8.0', draining: false }) }])
    expect(p.state).toBe('failed')
    expect(p.message).toMatch(/Back on 1\.8\.0; 1\.9\.0 was not installed/)
  })

  it('counts a restart or a reboot done when a fresh process answers', () => {
    for (const a of ['restart', 'reboot'] as const) {
      const seen = run(start(a), [{ at: t0 + 2000, status: status() }, { at: t0 + 4000, error: 'offline' }, { at: t0 + 6000, status: status({ started_at: 'later', draining: false }) }])
      expect(seen.map((p) => p.state)).toEqual(['running', 'running', 'done'])
      expect(seen[0].step).toBe('restart')
    }
  })

  it('catches a restart quick enough to fall between two polls', () => {
    const [p] = run(start('restart'), [{ at: t0 + 2000, status: status({ started_at: 'later', draining: false }) }])
    expect(p.state).toBe('done')
  })

  it('counts a stop done once the gateway has stayed away', () => {
    const seen = run(start('poweroff'), [{ at: t0 + 2000, error: 'offline' }, { at: t0 + 2000 + poweroffQuietMs - 1, error: 'offline' }, { at: t0 + 2000 + poweroffQuietMs, error: 'offline' }])
    expect(seen.map((p) => p.state)).toEqual(['running', 'running', 'done'])
  })

  it('says an action did not go ahead when the same process serves again', () => {
    const [p] = run(start('reboot'), [{ at: t0 + 2000, status: status({ draining: false }) }])
    expect(p.state).toBe('failed')
    expect(p.message).toMatch(/reboot did not go ahead/)
  })

  it('gives up at the deadline, and on a lost sign-in', () => {
    const s = start('restart')
    expect(observe(s, initialProgress, { at: s.deadline + 1, error: 'offline' })).toMatchObject({ state: 'failed', message: 'No answer within 10 minutes. Check the host.' })
    expect(observe(s, initialProgress, { at: t0 + 1, error: 'signed_out' }).state).toBe('failed')
  })

  it('stays put once finished', () => {
    const done: Progress = { state: 'done', step: 'back' }
    expect(observe(start('restart'), done, { at: t0, error: 'offline' })).toBe(done)
  })

  it('names the steps and the outcome', () => {
    expect(stepLabel('install', { action: 'update', target: '1.9.0' })).toBe('Installing 1.9.0')
    expect(stepLabel('restart', { action: 'reboot' })).toBe('Rebooting the host')
    expect(doneTitle({ action: 'update', target: '1.9.0' })).toBe('Updated to 1.9.0')
    expect(deadlineFor('update', 15, 0)).toBe(35 * 60_000)
  })

  it('tells the restart banner when a view is watching', () => {
    let calls = 0
    const off = progressWatch.subscribe(() => calls++)
    expect(progressWatch.active()).toBe(false)
    progressWatch.begin()
    expect(progressWatch.active()).toBe(true)
    progressWatch.end()
    progressWatch.end()
    expect(progressWatch.active()).toBe(false)
    off()
    expect(calls).toBe(3)
  })
})
