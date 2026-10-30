/** Where each dashboard number leads (2026-10-30): to the list holding
 *  exactly what it counted, never the whole page. Each mirrors the server's
 *  count: internal/overview foldTallies (audit events in the last 24 hours,
 *  every one, routine included), session.Repo.Count, and
 *  target.Repo.CountAttention and CountInventory (active only). `portal` is
 *  "/admin" or "/audit", whose pages these are. */

const events = (portal: string, filters: Record<string, string>) =>
  `${portal}/events?` + new URLSearchParams({ ...filters, range: '24h', routine: '1' }).toString()

export const drill = {
  failures: (portal: string) => events(portal, { outcome: 'failure' }),
  failedSignIns: (portal: string) => events(portal, { action: 'user.login', outcome: 'failure' }),
  refusedConnections: (portal: string) => events(portal, { action: 'session.connect', outcome: 'failure' }),
  auditEvents: (portal: string) => events(portal, {}),
  recordingsPlayed: (portal: string) => events(portal, { action: 'recording.view', outcome: 'success' }),
  recordingsDownloaded: (portal: string) => events(portal, { action: 'recording.download', outcome: 'success' }),
  openSessions: (portal: string) => `${portal}/sessions?open=1`,
  sessions24h: (portal: string) => `${portal}/sessions?range=24h`,
  hostsNeedingAttention: '/admin/hosts?attention=1',
  activeHosts: '/admin/hosts?status=active',
  activeDatabases: '/admin/databases?status=active',
  activeApplications: '/admin/applications?status=active',
}

/** A grant counts as expiring soon within this of its end: the access
 *  portal's strip counts them, and the Access page lists the same ones. */
export const expiringSoonMs = 60 * 60_000

export function expiresSoon(expiresAt: string | undefined, now = Date.now()): boolean {
  if (!expiresAt) return false
  const t = new Date(expiresAt).getTime()
  return t > now && t < now + expiringSoonMs
}

/** The access portal's strip, each opening the list it counted. */
export const accessDrill = {
  openSessions: '/sessions?open=1',
  pendingRequests: '/access?show=pending',
  expiringGrants: '/access?show=expiring',
}
