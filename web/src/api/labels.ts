import { shortId } from './format'
import type { Session } from './types'

/** sessionTarget names where a session went: the target's name, or for an
 *  autoscaling instance the group's name and the cloud instance id. The API
 *  resolves both at read time, and a retired target or group still labels its
 *  past sessions, so a bare id only shows for rows older than the name join. */
export function sessionTarget(s: Pick<Session, 'target_name' | 'asg_name' | 'instance_id' | 'target_id' | 'asg_instance_id'>): string {
  if (s.target_name) return s.target_name
  if (s.asg_name || s.instance_id) return [s.asg_name, s.instance_id].filter(Boolean).join(' · ')
  const id = s.target_id ?? s.asg_instance_id
  return id ? shortId(id) + '…' : '—'
}

/** sessionUser names who opened a session, falling back to a short id for a
 *  user row that no longer exists. */
export function sessionUser(s: Pick<Session, 'username' | 'user_id'>): string {
  return s.username || (s.user_id ? shortId(s.user_id) + '…' : '—')
}
