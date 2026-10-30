import { protocolName } from '../../api/format'
import type { AutoscalingGroup, Policy, PolicyGrant, Protocol, Target, TargetKind, TimeWindow } from '../../api/types'
import type { TagRow } from '../../components/tags'

// The access policy as the console edits it (ADR 0036): an audience and
// grants, each picking a kind, then targets with a protocol each or tags,
// then its own conditions. Pure functions; the editor and the list use them.

export const kinds: { kind: TargetKind; label: string }[] = [
  { kind: 'host', label: 'Host' },
  { kind: 'database', label: 'Database' },
  { kind: 'application', label: 'Application' },
  { kind: 'autoscaling', label: 'Autoscaling' },
]

/** What each kind serves; a grant offers nothing else. */
export const kindProtocols: Record<TargetKind, Protocol[]> = {
  host: ['ssh', 'rdp', 'vnc', 'winrm'],
  autoscaling: ['ssh', 'rdp', 'vnc', 'winrm'],
  database: ['database'],
  application: ['http'],
}

/** A target's kind: an engine makes it a database, an upstream an application. */
export function kindOf(t: Pick<Target, 'engine' | 'app_upstream'>): TargetKind {
  if (t.engine) return 'database'
  if (t.app_upstream) return 'application'
  return 'host'
}

/**
 * chipsFor is the protocols offered for one target in a grant: what a probe
 * found it serving, or before any probe what its operating system usually
 * serves. An autoscaling group offers its declared capabilities.
 */
export function chipsFor(kind: TargetKind, t: Pick<Target, 'capabilities' | 'os_family'> | Pick<AutoscalingGroup, 'capabilities' | 'os_family'>): Protocol[] {
  if (kind === 'database' || kind === 'application') return kindProtocols[kind]
  const served = kindProtocols[kind]
  const caps = (t.capabilities ?? []).filter((p) => served.includes(p))
  if (caps.length) return caps
  return usualFor(kind, t)
}

/** usualFor is what a target of this kind and operating system usually serves, probed or not. */
export function usualFor(kind: TargetKind, t: Pick<Target, 'os_family'> | Pick<AutoscalingGroup, 'os_family'>): Protocol[] {
  const served = kindProtocols[kind]
  if (kind !== 'host') return served
  switch (t.os_family) {
    case 'linux': return ['ssh', 'vnc']
    case 'windows': return ['rdp', 'winrm', 'ssh']
    default: return served
  }
}

/**
 * unfound splits a host's chips by what its last probe said (2026-10-30):
 * missing are the usual protocols the probe did not find, shown greyed so
 * the admin knows why one is absent; stale are chosen protocols it did not
 * find (a 1.7 policy converted with RDP on a Linux box), shown in warning so
 * they can be unticked. A host never probed has neither.
 */
export function unfound(t: Pick<Target, 'capabilities' | 'os_family'>, chosen: Protocol[]): { missing: Protocol[]; stale: Protocol[] } {
  const found = (t.capabilities ?? []).filter((p) => kindProtocols.host.includes(p))
  if (found.length === 0) return { missing: [], stale: [] }
  const stale = chosen.filter((p) => !found.includes(p))
  return { missing: usualFor('host', t).filter((p) => !found.includes(p) && !stale.includes(p)), stale }
}

/** A new grant of kind, with the defaults the server would fill. */
export function newGrant(kind: TargetKind = 'host', conditionsFrom?: PolicyGrant): PolicyGrant {
  const base: PolicyGrant = {
    kind, targets: [], access: 'standing', sign_in: 'target', require_mfa: true, allow_clipboard: false,
    allow_file_transfer: false, idle_timeout_minutes: 15, max_session_minutes: null, time_windows: [], retention_days: null,
  }
  if (!conditionsFrom) return base
  const { access, sign_in, require_mfa, allow_clipboard, allow_file_transfer, idle_timeout_minutes, max_session_minutes, time_windows, retention_days } = conditionsFrom
  return {
    ...base, access, sign_in: kind === 'application' ? 'target' : sign_in, require_mfa, allow_clipboard, allow_file_transfer,
    idle_timeout_minutes, max_session_minutes, time_windows: time_windows.map((w) => ({ ...w, days: [...w.days] })), retention_days,
  }
}

/** matchToRows lays a tag match out as rows; a key with two values is two rows. */
export function matchToRows(match?: Record<string, string[]>): TagRow[] {
  return Object.entries(match ?? {}).flatMap(([key, values]) => values.map((value) => ({ key, value })))
}

/**
 * rowsToMatch reads tag rows back into a match: every key must be present,
 * with one of the values given under it. Blank rows are dropped; a key or a
 * value alone is an error naming the row.
 */
export function rowsToMatch(rows: TagRow[]): { match: Record<string, string[]>; error?: string } {
  const match = new Map<string, string[]>()
  for (const [i, r] of rows.entries()) {
    const key = r.key.trim()
    const value = r.value.trim()
    if (!key && !value) continue
    if (!key) return { match: {}, error: `tag ${i + 1}: key is empty` }
    if (!value) return { match: {}, error: `tag ${key}: value is empty` }
    const values = match.get(key) ?? []
    if (values.includes(value)) return { match: {}, error: `tag ${key}: ${value} is given twice` }
    match.set(key, [...values, value])
  }
  return { match: Object.fromEntries(match) }
}

/** A tag match as one phrase: env prod|staging, tier web. */
export function matchPhrase(match: Record<string, string[]>): string {
  return Object.entries(match).map(([k, vs]) => `${k} ${vs.join('|')}`).join(', ')
}

function protos(ps: Protocol[]): string {
  return ps.map(protocolName).join(', ')
}

/**
 * grantSummary is one grant on one line, for the list and a collapsed card:
 * kind · targets (protocols) · tags (protocols) · access · MFA · idle, with
 * the clipboard, file transfer and own login said only when on.
 */
export function grantSummary(g: PolicyGrant, nameOf: (id: string) => string): string {
  const kind = kinds.find((k) => k.kind === g.kind)?.label ?? g.kind
  const implicit = g.kind === 'database' || g.kind === 'application'
  const parts = [kind]
  if (g.targets.length) parts.push(g.targets.map((t) => (implicit ? nameOf(t.id) : `${nameOf(t.id)} (${protos(t.protocols)})`)).join(', '))
  if (g.tags) parts.push(implicit ? matchPhrase(g.tags.match) : `${matchPhrase(g.tags.match)} (${protos(g.tags.protocols)})`)
  parts.push(g.access === 'approval' ? 'Approval' : 'Standing')
  if (g.require_mfa) parts.push('MFA')
  if (g.sign_in === 'own') parts.push('own login')
  if (g.allow_clipboard) parts.push('clipboard')
  if (g.allow_file_transfer) parts.push('files')
  parts.push(`${g.idle_timeout_minutes}m`)
  if (g.time_windows.length) parts.push(g.time_windows.length === 1 ? '1 window' : `${g.time_windows.length} windows`)
  return parts.join(' · ')
}

/** The grant as the editor holds it: tags as rows, numbers as text. */
export interface GrantDraft {
  id?: string
  kind: TargetKind
  targets: Record<string, Protocol[]>
  tagRows: TagRow[]
  tagProtocols: Protocol[]
  access: 'standing' | 'approval'
  sign_in: 'target' | 'own'
  require_mfa: boolean
  allow_clipboard: boolean
  allow_file_transfer: boolean
  idle: string
  max: string
  retention: string
  windows: TimeWindow[]
}

export function toDraft(g: PolicyGrant): GrantDraft {
  return {
    id: g.id, kind: g.kind,
    targets: Object.fromEntries(g.targets.map((t) => [t.id, [...t.protocols]])),
    tagRows: matchToRows(g.tags?.match),
    tagProtocols: g.tags ? [...g.tags.protocols] : g.kind === 'database' || g.kind === 'application' ? kindProtocols[g.kind] : ['ssh'],
    access: g.access, sign_in: g.sign_in, require_mfa: g.require_mfa, allow_clipboard: g.allow_clipboard,
    allow_file_transfer: g.allow_file_transfer, idle: String(g.idle_timeout_minutes),
    max: g.max_session_minutes ? String(g.max_session_minutes) : '', retention: g.retention_days ? String(g.retention_days) : '',
    windows: g.time_windows.map((w) => ({ ...w, days: [...w.days] })),
  }
}

/**
 * fromDraft turns a card back into a grant, or names what is wrong with it.
 * The checks are the server's, made here so the common ones never take a
 * round trip.
 */
export function fromDraft(d: GrantDraft, nameOf: (id: string) => string): { grant?: PolicyGrant; error?: string } {
  const implicit = d.kind === 'database' || d.kind === 'application'
  const targets = Object.entries(d.targets).map(([id, ps]) => ({ id, protocols: implicit ? kindProtocols[d.kind] : ps }))
  for (const t of targets) {
    if (t.protocols.length === 0) return { error: `${nameOf(t.id)} has no protocol` }
  }
  const { match, error } = rowsToMatch(d.tagRows)
  if (error) return { error }
  const hasTags = Object.keys(match).length > 0
  const tagProtocols = implicit ? kindProtocols[d.kind] : d.tagProtocols
  if (hasTags && tagProtocols.length === 0) return { error: 'choose a protocol for the tagged targets' }
  if (targets.length === 0 && !hasTags) return { error: 'choose targets, or match tags' }
  const idle = Number(d.idle)
  if (!Number.isInteger(idle) || idle < 1 || idle > 1440) return { error: 'idle timeout must be 1-1440 minutes' }
  const max = d.max.trim() ? Number(d.max) : null
  if (max !== null && (!Number.isInteger(max) || max < 1 || max > 10080)) return { error: 'maximum session must be 1-10080 minutes' }
  const retention = d.retention.trim() ? Number(d.retention) : null
  if (retention !== null && (!Number.isInteger(retention) || retention < 1 || retention > 3650)) return { error: 'keep recordings must be 1-3650 days' }
  return {
    grant: {
      ...(d.id ? { id: d.id } : {}),
      kind: d.kind, targets, ...(hasTags ? { tags: { match, protocols: tagProtocols } } : {}),
      access: d.access, sign_in: d.kind === 'application' ? 'target' : d.sign_in, require_mfa: d.require_mfa,
      allow_clipboard: d.allow_clipboard, allow_file_transfer: d.allow_file_transfer, idle_timeout_minutes: idle,
      max_session_minutes: max, time_windows: d.windows.map((w) => ({ ...w, tz: w.tz || 'UTC' })), retention_days: retention,
    },
  }
}

/** whoSummary names a policy's audience: the groups, then how many users. */
export function whoSummary(p: Policy, groupName: (id: string) => string, userName: (id: string) => string): string {
  const groups = p.subjects.filter((s) => s.kind === 'group').map((s) => groupName(s.id))
  const users = p.subjects.filter((s) => s.kind === 'user').map((s) => userName(s.id))
  if (users.length <= 2) return [...groups, ...users].join(', ')
  return [...groups, `${users.length} users`].join(', ')
}
