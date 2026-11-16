import { fmtTime } from '../../api/format'
import type { AccessRequest } from '../../api/types'

/** Scope is whose requests a queue holds: every request, for an
 *  administrator; those the grants name the caller for, for an approver
 *  (ADR 0049). */
export type Scope = 'all' | 'mine'

/** query is the list's address for a scope and a status. */
export function query(scope: Scope, status?: string): string {
  const parts = [scope === 'mine' ? 'scope=mine' : '', status ? `status=${status}` : ''].filter(Boolean)
  return '/access-requests' + (parts.length ? '?' + parts.join('&') : '')
}

/** who and what name a request's requester and target; the API resolves
 *  names at read time, for autoscaling groups too, and a retired target
 *  still labels its old requests; the id is the last resort. */
export const who = (r: AccessRequest) => r.username || r.user_id
export const what = (r: AccessRequest) => r.target_name || r.asg_name || r.target_id || r.asg_id || '—'

/** approverNames is the Approvers cell: the groups and people the eligible
 *  grants name, or a dash when an administrator decides. */
export function approverNames(r: AccessRequest): string {
  return r.approvers?.length ? r.approvers.map((a) => a.name).join(', ') : '—'
}

/** decided says what became of a linked request that no longer waits here. */
export function decided(r: AccessRequest): string {
  const whom = who(r)
  const thing = r.target_name || r.asg_name || r.target_id || r.asg_id || 'a target'
  const by = r.approver_username ? ` by ${r.approver_username}` : ''
  const when = r.decided_at ? ` ${fmtTime(r.decided_at)}` : ''
  switch (r.status) {
    case 'pending':
      return r.named ? `${whom}'s request for ${thing} waits for ${approverNames(r)}.` : `${whom}'s request for ${thing} waits below.`
    case 'approved':
      return `${whom}'s request for ${thing} was already approved${by}${when}.`
    case 'denied':
      return `${whom}'s request for ${thing} was already denied${by}${when}.`
    case 'revoked':
      return `${whom}'s grant on ${thing} was revoked${when}.`
    case 'cancelled':
      return `${whom} cancelled the request for ${thing}${when}.`
    default:
      return `${whom}'s request for ${thing} has ${r.status}.`
  }
}
