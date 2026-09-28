import type { User } from '../api/types'

/** canConnect mirrors the server's rule (ADR 0006): the user and admin roles
 *  may see targets and open sessions; an account holding only auditor is
 *  review-only and has no user portal. */
export function canConnect(user: Pick<User, 'roles'> | null | undefined): boolean {
  return !!user && (user.roles.includes('user') || user.roles.includes('admin'))
}

/** homeFor is where an account lands after sign-in and when it is turned away
 *  from a portal it may not enter: the user portal when it can connect, the
 *  audit portal for a review-only account. */
export function homeFor(user: Pick<User, 'roles'> | null | undefined): string {
  if (canConnect(user)) return '/'
  if (user?.roles.includes('auditor')) return '/audit'
  return '/'
}
