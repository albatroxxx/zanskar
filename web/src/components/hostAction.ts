import type { ConfigResult, SystemStatus, UpdateStatus } from '../api/types'

/** What the gear and the bell can ask the gateway to do (ADR 0032). */
export type HostAction = 'update' | 'restart' | 'reboot' | 'poweroff' | 'config'

/** A stage the progress view lists; 'restart' also covers the gateway being away. */
export type Step = 'drain' | 'install' | 'restart' | 'back'

/** The stages each action goes through, in order. */
export const stepsFor: Record<HostAction, Step[]> = {
  update: ['drain', 'install', 'restart', 'back'],
  restart: ['drain', 'restart', 'back'],
  reboot: ['drain', 'restart', 'back'],
  poweroff: ['drain', 'restart'],
  config: ['drain', 'install', 'restart', 'back'],
}

/** Start is what was asked, and of which process. */
export interface Start {
  action: HostAction
  /** The version an update installs; the request id of a config change. */
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
  /** Every report of the installer the view caught, each once, in order. A
   *  stage that began and ended between two polls is not among them. */
  seen?: string[]
  /** The service's last lines when an install settings change did not
   *  come back: shown folded under the message, never in it. */
  log?: string
  /** When the gateway was first found away (ms); a power-off is done once it stays away. */
  offlineSince?: number
}

/** One poll: the status, the installer's report, or why neither could be read. */
export interface Observation {
  at: number
  status?: SystemStatus
  update?: UpdateStatus | null
  /** The root helper's last answer, for a config change. */
  config?: ConfigResult | null
  error?: 'offline' | 'signed_out'
}

/** pacing is how often the progress view asks; tests shorten it. fastMs is
 *  the pace while the installer works and the gateway restarts, stages that
 *  last a second or two (an update took about 7 seconds from the request to the
 *  new process, 2026-11-05): at the slow pace most were never seen. */
export const pacing = { pollMs: 2000, fastMs: 500 }

/** pollDelay is how long to wait before asking again, by the stage shown. */
export function pollDelay(step: Step): number {
  return step === 'install' || step === 'restart' ? pacing.fastMs : pacing.pollMs
}

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
  if (start.action === 'config') return observeConfig(start, prev, o, s)
  const inst = thisInstall(start, o.update)
  // The installer's words, each once, in the order they were caught: a stage
  // that ends between two polls is never seen, but one that is, is kept.
  const seen = noted(prev.seen, inst?.message)
  if (s.started_at !== start.startedAt) {
    if (start.action === 'update' && s.version !== start.target) {
      return { state: 'failed', step: 'back', message: `Back on ${s.version}; ${start.target} was not installed.${inst?.message ? ' ' + inst.message : ''}` }
    }
    return { state: 'done', step: 'back', message: inst?.message, seen }
  }
  if (inst?.state === 'failed') return { state: 'failed', step: 'install', message: inst.message || 'The installer failed.' }
  if (o.at > start.deadline) return timedOut(start, prev)
  if (s.draining) {
    if (inst) return { state: 'running', step: inst.state === 'done' ? 'restart' : 'install', message: inst.message, seen }
    if (s.live_sessions > 0) return { state: 'running', step: 'drain', live: s.live_sessions, until: s.drain?.deadline, seen }
    return { state: 'running', step: start.action === 'update' ? 'install' : 'restart', seen }
  }
  // The same process, serving again: cancelled, or the action failed.
  return { state: 'failed', step: prev.step, message: `The ${noun(start)} did not go ahead. Events has the reason.` }
}

/** sentence reads the helper's words, written in Go's lower-case style, as
 *  the console's: a capital first and a full stop last. */
export function sentence(s: string | undefined): string {
  const t = (s ?? '').trim()
  if (!t) return ''
  return t[0].toUpperCase() + t.slice(1) + (/[.!?…]$/.test(t) ? '' : '.')
}

/**
 * observeConfig follows a change of the environment file (ADR 0020, amended
 * 2026-10-30): the helper's answer for this request decides. Refused, it
 * never restarted; rolled back, the gateway is back on the previous file;
 * applied, done once a fresh process answers.
 */
function observeConfig(start: Start, prev: Progress, o: Observation, s: SystemStatus): Progress {
  const res = o.config && o.config.id === start.target ? o.config : undefined
  if (res?.state === 'refused') return { state: 'failed', step: 'install', message: sentence(res.message) || 'The change was refused.' }
  if (res?.state === 'rolled_back') {
    return { state: 'failed', step: 'back', message: sentence(res.message) || 'The gateway did not come back; the previous settings are back.', log: res.log || undefined }
  }
  if (o.at > start.deadline) return timedOut(start, prev)
  if (s.started_at !== start.startedAt) {
    // A fresh process: done once the helper says the change held.
    return res?.state === 'applied' ? { state: 'done', step: 'back' } : { state: 'running', step: 'restart' }
  }
  if (s.draining) {
    if (s.live_sessions > 0) return { state: 'running', step: 'drain', live: s.live_sessions, until: s.drain?.deadline }
    return { state: 'running', step: 'install' }
  }
  return { state: 'failed', step: prev.step, message: 'The change did not go ahead. Events has the reason.' }
}

/** noted adds the installer's latest words to those already caught, once. */
function noted(seen: string[] | undefined, message: string | undefined): string[] | undefined {
  const m = message?.trim()
  if (!m || seen?.includes(m)) return seen
  return [...(seen ?? []), m]
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
      return start.action === 'config' ? 'Applying the settings' : `Installing ${start.target}`
    case 'restart':
      return start.action === 'reboot' ? 'Rebooting the host' : start.action === 'poweroff' ? 'Stopping the host' : 'Restarting'
    case 'back':
      return start.action === 'update' ? `Back on ${start.target}` : start.action === 'config' ? 'Back with the new settings' : 'Back online'
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
    case 'config':
      return 'Install settings applied'
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
