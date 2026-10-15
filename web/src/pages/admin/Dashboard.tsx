import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { engineName, fmtBytes, fmtTime } from '../../api/format'
import type { AdminOverview, SystemMetrics, SystemStatus, TLSStatus } from '../../api/types'
import { StateIcon, TileIcon } from '../../components/icons'
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
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  // A failed read must not look like a quiet system (the Approvals rule).
  const [err, setErr] = useState('')

  useEffect(() => {
    api.get<AdminOverview>('/admin/overview').then(setOverview).catch((e) => setErr(errorMessage(e)))
    api.get<SystemStatus>('/admin/system/status').then(setStatus).catch((e) => setErr(errorMessage(e)))
    api.get<TLSStatus>('/admin/tls').then(setTls).catch((e) => setErr(errorMessage(e)))
    api.get<SystemMetrics>('/admin/system/metrics').then(setMetrics).catch((e) => setErr(errorMessage(e)))
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
        <StatTile value={o && o.pending_requests} label="Pending approvals" icon={<TileIcon kind="approvals" />} to="/admin/approvals" tone="warn" />
        <StatTile value={attention} label="Hosts needing attention" icon={<TileIcon kind="attention" />} to="/admin/hosts" tone="warn" />
        <StatTile value={o && o.audit_24h.failed_logins} label="Failed sign-ins (24h)" icon={<TileIcon kind="key" />} to="/admin/events" tone="warn" />
        <StatTile value={o && o.audit_24h.refused_connects} label="Refused connections (24h)" icon={<TileIcon kind="ban" />} to="/admin/events" tone="warn" />
      </div>

      <h2 className="stat-section">Activity</h2>
      <div className="stat-grid">
        <StatTile value={o && o.sessions.open} label="Open sessions" icon={<TileIcon kind="session" />} to="/admin/sessions" />
        <StatTile value={o && o.sessions.started_24h} label="Sessions (24h)" icon={<TileIcon kind="clock" />} to="/admin/sessions" />
        <StatTile value={o && o.audit_24h.failures} label="Failures (24h)" icon={<TileIcon kind="attention" />} to="/admin/events" />
        <StatTile value={o && o.audit_24h.events} label="Audit events (24h)" icon={<TileIcon kind="list" />} to="/admin/events" />
      </div>

      <h2 className="stat-section">Inventory</h2>
      <div className="stat-grid">
        <StatTile value={o && o.inventory.hosts} label="Hosts" icon={<TileIcon kind="server" />} detail={o ? mix(o.inventory.hosts_by_os, osLabel) : undefined} to="/admin/hosts" />
        <StatTile value={o && o.inventory.databases} label="Databases" icon={<TileIcon kind="db" />} detail={o ? mix(o.inventory.databases_by_engine, (e) => engineName(e)) : undefined} to="/admin/databases" />
        <StatTile
          value={o && o.autoscaling.groups}
          label="Autoscaling groups"
          icon={<TileIcon kind="stack" />}
          detail={o && o.autoscaling.instances > 0 ? `${o.autoscaling.healthy_instances} of ${o.autoscaling.instances} instances healthy` : undefined}
          meter={
            o && o.autoscaling.instances > 0
              ? {
                  fraction: o.autoscaling.healthy_instances / o.autoscaling.instances,
                  tone: o.autoscaling.healthy_instances === 0 ? 'danger' : o.autoscaling.healthy_instances < o.autoscaling.instances ? 'warn' : undefined,
                }
              : undefined
          }
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
            {metrics && <HostFacts m={metrics} />}
          </>
        )}
      </div>
    </>
  )
}

/** diskTone marks a volume an admin should act on: warn under 10% or 5 GB
 *  free, danger under 5%. A full recordings volume stops sessions being
 *  recorded. */
function diskTone(d: { total_bytes: number; free_bytes: number }): 'warn' | 'danger' | undefined {
  if (d.free_bytes < d.total_bytes / 20) return 'danger'
  if (d.free_bytes < d.total_bytes / 10 || d.free_bytes < 5 * 1024 ** 3) return 'warn'
  return undefined
}

/** Gauge is one ratio against its limit: a label, the reading in words, and
 *  a meter whose fill escalates with the tone. */
function Gauge({ label, reading, fraction, tone }: { label: string; reading: ReactNode; fraction: number; tone?: 'warn' | 'danger' }) {
  const pct = Math.round(Math.max(0, Math.min(1, fraction)) * 100)
  return (
    <div className="gauge">
      <div className="label">{label}</div>
      <div className="reading">{reading}</div>
      <div className={'meter' + (tone ? ' ' + tone : '')} role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <i style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

/** HostFacts is the gateway host right now: a gauge per ratio, then a line
 *  for the facts that are not ratios. Words carry every state the colour
 *  does. */
function HostFacts({ m }: { m: SystemMetrics }) {
  const used = m.memory ? m.memory.total_bytes - m.memory.available_bytes : 0
  return (
    <>
      <div className="gw-grid">
        {m.load && m.cpus > 0 && (
          <Gauge
            label={`Load (${m.cpus} cores)`}
            reading={<><b>{m.load.one.toFixed(2)}</b> now · {m.load.fifteen.toFixed(2)} over 15 min</>}
            fraction={m.load.one / m.cpus}
            tone={m.load.one >= m.cpus ? 'danger' : m.load.one >= m.cpus * 0.85 ? 'warn' : undefined}
          />
        )}
        {m.memory && (
          <Gauge
            label="Memory"
            reading={<><b>{fmtBytes(used)}</b> used of {fmtBytes(m.memory.total_bytes)}</>}
            fraction={used / m.memory.total_bytes}
            tone={used >= m.memory.total_bytes * 0.95 ? 'danger' : used >= m.memory.total_bytes * 0.85 ? 'warn' : undefined}
          />
        )}
        {m.disks.map((d) => (
          <Gauge
            key={d.path}
            label={d.system ? 'System disk' : d.what === 'recordings' ? 'Recording' : `${d.what[0].toUpperCase() + d.what.slice(1)} disk`}
            reading={
              <>
                <b>{fmtBytes(d.free_bytes)}</b> free of {fmtBytes(d.total_bytes)}
                {diskTone(d) && (
                  <>
                    {' '}
                    <StateIcon state={diskTone(d) as 'warn' | 'danger'} label={`Low space: ${fmtBytes(d.free_bytes)} free`} />
                  </>
                )}
              </>
            }
            fraction={1 - d.free_bytes / d.total_bytes}
            // The meter's tone follows its own geometry (how full); the badge
            // alone carries the absolute under-5-GB floor, so a tiny volume
            // never shows an alarmed near-empty bar.
            tone={d.free_bytes < d.total_bytes / 20 ? 'danger' : d.free_bytes < d.total_bytes / 10 ? 'warn' : undefined}
          />
        ))}
      </div>
      <p className="muted" style={{ margin: '12px 0 0' }}>
        {m.database_sessions} database session container{m.database_sessions === 1 ? '' : 's'}
        {m.guacd && (
          <>
            {' · '}guacd {m.guacd.reachable ? 'reachable' : <Badge tone="danger">unreachable at {m.guacd.address}</Badge>}
          </>
        )}
      </p>
    </>
  )
}
