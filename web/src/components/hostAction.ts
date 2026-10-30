import type { SystemStatus, UpdateStatus } from '../api/types'

/** What the gear and the bell can ask the gateway to do (ADR 0032). */
export type HostAction = 'update' | 'restart' | 'reboot' | 'poweroff'

/** A stage the progress view lists; 'restart' also covers the gateway being away. */
export type Step = 'drain' | 'install' | 'restart' | 'back'

/** The stages each action goes through, in order. */
export const stepsFor: Record<HostAction, Step[]> = {
  update: ['drain', 'install', 'restart', 'back'],
  restart: ['drain', 'restart', 'back'],
  reboot: ['drain', 'restart', 'back'],
  poweroff: ['drain', 'restart'],
}

/** Start is what was asked, and of which process. */
export interface Start {
  action: HostAction
  /** The version an update installs. */
  target?: string
  /** started_at of the process that was asked: a different one is the fresh process. */
  startedAt: string
  /** The installer's report before the request (its time), so an old report is not read as this one's. */
  installBefore?: string
  /** When it was asked, and when to give up, in browser milliseconds. */
  at: number
  deadline: number
}

export interface Progress {
  state: 'running' | 'done' | 'failed' | 'cancelled'
  step: Step
  /** Live sessions still open while draining, and the drain's deadline. */
  live?: number
  until?: string
  /** The installer's words, or why it failed. */
  message?: string
  /** When the gateway was first found away (ms); a power-off is done once it stays away. */
  offlineSince?: number
}

/** One poll: the status, the installer's report, or why neither could be read. */
export interface Observation {
  at: number
  status?: SystemStatus
  update?: UpdateStatus | null
  error?: 'offline' | 'signed_out'
}

/** pacing is how often the progress view asks; tests shorten it. */
export const pacing = { pollMs: 2000 }

/** How long a gateway asked to power off must stay away before it counts as stopped. */
export const poweroffQuietMs = 15_000

/** deadlineFor allows the drain plus the work after it: an install takes longest. */
export function deadlineFor(action: HostAction, waitMinutes: number, now: number): number {
  const after = action === 'update' ? 20 : action === 'poweroff' ? 5 : 10
  return now + (Math.max(0, waitMinutes) + after) * 60_000
}

export const initialProgress: Progress = { state: 'running', step: 'drain' }

/**
 * observe moves the progress on by one poll. Success is judged by what the
 * gateway says, never by time alone: a fresh process (a new started_at) on
 * the version asked for is an update done; a fresh process is a restart or
 * a reboot done; a power-off is done once the gateway has stayed away. The
 * same process no longer draining means the action did not go ahead.
 */
export function observe(start: Start, prev: Progress, o: Observation): Progress {
  if (prev.state !== 'running') return prev
  if (o.error === 'signed_out') return { ...prev, state: 'failed', message: 'Signed out. Sign in again to see how it ended.' }
  if (o.error === 'offline' || !o.status) {
    const offlineSince = prev.offlineSince ?? o.at
    if (start.action === 'poweroff' && o.at - offlineSince >= poweroffQuietMs) return { state: 'done', step: 'restart', offlineSince }
    if (o.at > start.deadline) return timedOut(start, prev)
    return { ...prev, step: 'restart', live: undefined, until: undefined, offlineSince }
  }
  const s = o.status
  const inst = thisInstall(start, o.update)
  if (s.started_at !== start.startedAt) {
    if (start.action === 'update' && s.version !== start.target) {
      return { state: 'failed', step: 'back', message: `Back on ${s.version}; ${start.target} was not installed.${inst?.message ? ' ' + inst.message : ''}` }
    }
    return { state: 'done', step: 'back' }
  }
  if (inst?.state === 'failed') return { state: 'failed', step: 'install', message: inst.message || 'The installer failed.' }
  if (o.at > start.deadline) return timedOut(start, prev)
  if (s.draining) {
    if (inst) return { state: 'running', step: inst.state === 'done' ? 'restart' : 'install', message: inst.message }
    if (s.live_sessions > 0) return { state: 'running', step: 'drain', live: s.live_sessions, until: s.drain?.deadline }
    return { state: 'running', step: start.action === 'update' ? 'install' : 'restart' }
  }
  // The same process, serving again: cancelled, or the action failed.
  return { state: 'failed', step: prev.step, message: `The ${noun(start)} did not go ahead. Events has the reason.` }
}

/** thisInstall is the installer's report for this request, if it has written one. */
function thisInstall(start: Start, u?: UpdateStatus | null) {
  const inst = u?.install
  if (start.action !== 'update' || !inst || inst.version !== start.target || inst.at === start.installBefore) return undefined
  return inst
}

function timedOut(start: Start, prev: Progress): Progress {
  const minutes = Math.round((start.deadline - start.at) / 60_000)
  return { ...prev, state: 'failed', message: `No answer within ${minutes} minutes. Check the host.` }
}

function noun(start: Start): string {
  return start.action === 'poweroff' ? 'stop' : start.action
}

/** stepLabel names a stage for this action. */
export function stepLabel(step: Step, start: Pick<Start, 'action' | 'target'>): string {
  switch (step) {
    case 'drain':
      return 'Waiting for live sessions'
    case 'install':
      return `Installing ${start.target}`
    case 'restart':
      return start.action === 'reboot' ? 'Rebooting the host' : start.action === 'poweroff' ? 'Stopping the host' : 'Restarting'
    case 'back':
      return start.action === 'update' ? `Back on ${start.target}` : 'Back online'
  }
}

/** doneTitle is the line beside the green tick. */
export function doneTitle(start: Pick<Start, 'action' | 'target'>): string {
  switch (start.action) {
    case 'update':
      return `Updated to ${start.target}`
    case 'restart':
      return 'Gateway restarted'
    case 'reboot':
      return 'Host rebooted'
    case 'poweroff':
      return 'Host stopped'
  }
}

// While a progress view is open it owns the restart: the restart banner must
// not reload the page under it before the green tick shows.
let watching = 0
const listeners = new Set<() => void>()

/** progressWatch is the count of open progress views, for useSyncExternalStore. */
export const progressWatch = {
  begin() {
    watching++
    listeners.forEach((l) => l())
  },
  end() {
    watching = Math.max(0, watching - 1)
    listeners.forEach((l) => l())
  },
  subscribe(l: () => void) {
    listeners.add(l)
    return () => listeners.delete(l)
  },
  active: () => watching > 0,
}
