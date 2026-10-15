import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { engineName, fmtTime } from '../../api/format'
import type { AdminOverview, SystemStatus, TLSStatus } from '../../api/types'
import { Alert, Badge, PageHead, StatTile } from '../../components/ui'

/** mix says what a count is made of — "2 Linux · 1 Windows" — in a tile's
 *  detail line, largest first, empty when there is nothing to split. */
function mix(by: Record<string, number>, name: (key: string) => string): string | undefined {
  const parts = Object.entries(by)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${n} ${name(k)}`)
  return parts.length ? parts.join(' · ') : undefined
}

const osLabel = (os: string) => (os === 'linux' ? 'Linux' : os === 'windows' ? 'Windows' : os)

/** A certificate inside this window of its expiry is worth a warning. */
const certWarnDays = 30

/** uptime says how long the gateway has run, in the largest unit that reads
 *  well: "41 minutes", "18 hours", "12 days". */
function uptime(seconds: number): string {
  const n = (v: number, unit: string) => `${v} ${unit}${v === 1 ? '' : 's'}`
  if (seconds < 3600) return n(Math.max(1, Math.floor(seconds / 60)), 'minute')
  if (seconds < 48 * 3600) return n(Math.floor(seconds / 3600), 'hour')
  return n(Math.floor(seconds / 86400), 'day')
}

/** Dashboard is where an admin lands (ADR 0029): what waits on a decision,
 *  what is live, and whether the gateway itself is healthy. Every number links
 *  to the page that manages it; the dashboard itself changes nothing. */
export function Dashboard() {
  const [overview, setOverview] = useState<AdminOverview | null>(null)
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [tls, setTls] = useState<TLSStatus | null>(null)
  // A failed read must not look like a quiet system (the Approvals rule).
  const [err, setErr] = useState('')

  useEffect(() => {
    api.get<AdminOverview>('/admin/overview').then(setOverview).catch((e) => setErr(errorMessage(e)))
    api.get<SystemStatus>('/admin/system/status').then(setStatus).catch((e) => setErr(errorMessage(e)))
    api.get<TLSStatus>('/admin/tls').then(setTls).catch((e) => setErr(errorMessage(e)))
  }, [])

  const o = overview
  const attention = o ? o.targets.host_key_pending + o.targets.host_key_changed + o.targets.certificate_pending : null
  const cert = tls?.active
  const certDays = cert ? Math.floor((new Date(cert.not_after).getTime() - Date.now()) / 86400000) : null

  return (
    <>
      <PageHead title="Dashboard" />
      {err && <Alert tone="danger">The dashboard could not be fully loaded: {err}</Alert>}

      <h2 className="stat-section">Needs attention</h2>
      <div className="stat-grid">
        <StatTile value={o && o.pending_requests} label="Pending approvals" to="/admin/approvals" tone="warn" />
        <StatTile value={attention} label="Hosts needing attention" to="/admin/hosts" tone="warn" />
        <StatTile value={o && o.audit_24h.failed_logins} label="Failed sign-ins (24h)" to="/admin/events" tone="warn" />
        <StatTile value={o && o.audit_24h.refused_connects} label="Refused connections (24h)" to="/admin/events" tone="warn" />
      </div>

      <h2 className="stat-section">Activity</h2>
      <div className="stat-grid">
        <StatTile value={o && o.sessions.open} label="Open sessions" to="/admin/sessions" />
        <StatTile value={o && o.sessions.started_24h} label="Sessions (24h)" to="/admin/sessions" />
        <StatTile value={o && o.audit_24h.failures} label="Failures (24h)" to="/admin/events" />
        <StatTile value={o && o.audit_24h.events} label="Audit events (24h)" to="/admin/events" />
      </div>

      <h2 className="stat-section">Inventory</h2>
      <div className="stat-grid">
        <StatTile value={o && o.inventory.hosts} label="Hosts" detail={o ? mix(o.inventory.hosts_by_os, osLabel) : undefined} to="/admin/hosts" />
        <StatTile value={o && o.inventory.databases} label="Databases" detail={o ? mix(o.inventory.databases_by_engine, (e) => engineName(e)) : undefined} to="/admin/databases" />
        <StatTile
          value={o && o.autoscaling.groups}
          label="Autoscaling groups"
          detail={o && o.autoscaling.instances > 0 ? `${o.autoscaling.healthy_instances} of ${o.autoscaling.instances} instances healthy` : undefined}
          to="/admin/autoscaling"
        />
      </div>

      <h2 className="stat-section">Gateway</h2>
      <div className="card">
        {status === null ? (
          <p className="muted" style={{ margin: 0 }}>Loading…</p>
        ) : (
          <>
            {status.restart_required && (
              <Alert tone="warn">The environment file changed since the gateway started; a restart applies it. Restart from <Link to="/admin/settings">Settings</Link>.</Alert>
            )}
            {status.draining && <Alert tone="warn">A restart is in progress: the gateway is draining live sessions.</Alert>}
            <p style={{ margin: 0 }}>
              Zanskar {status.version}, up {uptime(status.uptime_seconds)}
              {status.supervisor !== 'unknown' && <> under {status.supervisor}</>}.{' '}
              {cert && (
                <>
                  The TLS certificate{cert.self_signed ? ' (self-signed)' : ''} is valid until {fmtTime(cert.not_after)}
                  {certDays !== null && certDays <= certWarnDays && (
                    <>
                      {' '}
                      <Badge tone={certDays <= 7 ? 'danger' : 'warn'}>{certDays <= 0 ? 'expired' : `${certDays} days left`}</Badge>
                    </>
                  )}
                  . Manage it in <Link to="/admin/settings">Settings</Link>.
                </>
              )}
            </p>
          </>
        )}
      </div>
    </>
  )
}
