import type { Role } from './types'

/** normalizeRoles is roles as the gateway keeps them (user.NormalizeRoles):
 *  admin alone when it is there, since an administrator reviews what an
 *  auditor reviews and connects as a user does; otherwise auditor and user,
 *  each once. */
export function normalizeRoles(roles: Role[]): Role[] {
  if (roles.includes('admin')) return ['admin']
  return (['auditor', 'user'] as Role[]).filter((r) => roles.includes(r))
}
