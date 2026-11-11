// The words the console shows for each state the gateway computes (ADR 0047).
// One table, one badge: a page reads a record's `state` and never works it
// out from raw fields. The keys are the lifecycles the code declares, and
// the Go test TestLifecyclesHaveConsoleLabels fails when a declared state has
// no entry here or an entry names a state the gateway never sends. Keep one
// state per line in this shape; the test reads the file, not the module.

export type StateTone = 'ok' | 'warn' | 'danger' | 'accent'

export interface StateLabel {
  label: string
  tone?: StateTone
}

export const stateLabels = {
  session: {
    live: { label: 'live', tone: 'accent' },
    ended: { label: 'ended' },
  },
  recording: {
    recording: { label: 'recording', tone: 'accent' },
    finished: { label: 'saved' },
    lost: { label: 'lost', tone: 'danger' },
    purged: { label: 'deleted' },
    discarded: { label: 'discarded' },
  },
  target: {
    active: { label: 'active' },
    disabled: { label: 'disabled' },
    retired: { label: 'retired' },
  },
  host_key: {
    unknown: { label: 'unknown' },
    pending: { label: 'pending', tone: 'warn' },
    trusted: { label: 'trusted', tone: 'ok' },
    changed: { label: 'changed', tone: 'danger' },
  },
  certificate_pin: {
    none: { label: 'no certificate' },
    pinned: { label: 'pinned', tone: 'ok' },
    changed: { label: 'changed', tone: 'danger' },
  },
  autoscaling_instance: {
    healthy: { label: 'healthy', tone: 'ok' },
    unhealthy: { label: 'unhealthy', tone: 'danger' },
    terminated: { label: 'terminated' },
  },
  user: {
    active: { label: 'active', tone: 'ok' },
    locked_out: { label: 'locked out', tone: 'warn' },
    disabled: { label: 'disabled', tone: 'warn' },
    locked: { label: 'locked', tone: 'warn' },
  },
  access_request: {
    pending: { label: 'pending', tone: 'warn' },
    approved: { label: 'approved', tone: 'ok' },
    denied: { label: 'denied', tone: 'danger' },
    expired: { label: 'expired' },
    revoked: { label: 'revoked' },
  },
  api_token: {
    active: { label: 'active', tone: 'ok' },
    expired: { label: 'expired', tone: 'warn' },
    revoked: { label: 'revoked', tone: 'danger' },
  },
  authority_rotation: {
    none: { label: 'current' },
    prepared: { label: 'next key prepared', tone: 'warn' },
    cut_over: { label: 'cut over', tone: 'warn' },
  },
  access_review: {
    never_reviewed: { label: 'never reviewed' },
    current: { label: 'reviewed' },
    due: { label: 'review due', tone: 'warn' },
  },
  environment_file: {
    unchanged: { label: 'unchanged' },
    changed: { label: 'changed, restart required', tone: 'warn' },
    missing: { label: 'missing' },
    unreadable: { label: 'cannot be checked', tone: 'warn' },
    none: { label: 'none' },
  },
  tls_certificate_source: {
    uploaded: { label: 'uploaded' },
    file: { label: 'from ZANSKAR_TLS_CERT' },
    generated: { label: 'self-signed' },
  },
} as const satisfies Record<string, Record<string, StateLabel>>

export type Lifecycle = keyof typeof stateLabels
export type StateOf<L extends Lifecycle> = keyof (typeof stateLabels)[L] & string

/** stateLabel is the words and tone for one state; an unknown word (a newer
 *  gateway) shows as itself with no tone rather than nothing. */
export function stateLabel(lifecycle: Lifecycle, state: string | undefined): StateLabel {
  const table = stateLabels[lifecycle] as Record<string, StateLabel>
  if (state && table[state]) return table[state]
  return { label: (state ?? '').replace(/_/g, ' ') }
}

/** recordingGone says a recording has no file left to play or download:
 *  retention deleted it, or it was discarded with its session. A lost one
 *  keeps its Play, since part of the file may be there (2026-11-11, owner:
 *  a deleted recording was offered for review and play). */
export function recordingGone(state: string | undefined): boolean {
  return state === 'purged' || state === 'discarded'
}

/** capitalised is a label with its first letter up, for the places that speak
 *  in sentence case (a table's status cell), from the one lower-case table. */
export function capitalised(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s
}
