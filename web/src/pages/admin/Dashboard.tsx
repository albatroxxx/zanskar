import { Fragment, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { consoleZone, engineName, fmtBytes, fmtTime, zoneLabel } from '../../api/format'
import type { AdminOverview, SystemMetrics, SystemStatus, TLSStatus } from '../../api/types'
import { StateIcon, TileIcon } from '../../components/icons'
import { drill } from '../../api/drilldown'
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
/** How often the gateway card's numbers are read again while the page is open. */
const METRICS_EVERY_MS = 10_000

export function Dashboard() {
  // Read once per mount: a clock read during render is impure and would
  // make re-renders disagree with each other.
  const [now] = useState(() => Date.now())
  const [overview, setOverview] = useState<AdminOverview | null>(null)
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [tls, setTls] = useState<TLSStatus | null>(null)
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const [skew, setSkew] = useState(0)
  // A failed read must not look like a quiet system (the Approvals rule).
  const [err, setErr] = useState('')

  useEffect(() => {
    api.get<AdminOverview>('/admin/overview').then(setOverview).catch((e) => setErr(errorMessage(e)))
    const asked = Date.now()
    api
      .get<SystemStatus>('/admin/system/status')
      .then((st) => {
        setStatus(st)
        // The gateway's clock against the browser's, halfway through the
        // round trip; the clock shows the gateway's time.
        const at = st.now ? Date.parse(st.now) : Number.NaN
        if (!Number.isNaN(at)) setSkew(at - (asked + Date.now()) / 2)
      })
      .catch((e) => setErr(errorMessage(e)))
    api.get<TLSStatus>('/admin/tls').then(setTls).catch((e) => setErr(errorMessage(e)))
    // The host's numbers are live: read again every ten seconds while the
    // page is open, so a gauge moves instead of standing where the page
    // found it.
    const metrics = () => api.get<SystemMetrics>('/admin/system/metrics').then(setMetrics).catch((e) => setErr(errorMessage(e)))
    void metrics()
    const every = setInterval(() => void metrics(), METRICS_EVERY_MS)
    return () => clearInterval(every)
  }, [])

  const o = overview
  // Each host once, however many decisions it waits on: what the list it
  // opens holds.
  const attention = o ? o.targets.needing_attention : null
  const cert = tls?.active
  const certDays = cert ? Math.floor((new Date(cert.not_after).getTime() - now) / 86400000) : null

  return (
    <>
      <PageHead title="Dashboard" />
      {err && <Alert tone="danger">The dashboard could not be fully loaded: {err}</Alert>}

      {/* The tiles, inventory first, on the left; the gateway itself (its
          clock, health and storage) in a column on their right. */}
      <div className="dash">
        <div className="dash-main">
          <section className="dash-sec">
            <h2 className="stat-section">Inventory</h2>
            <div className="stat-grid">
              <StatTile value={o && o.inventory.hosts} label="Hosts" icon={<TileIcon kind="server" />} detail={o ? mix(o.inventory.hosts_by_os, osLabel) : undefined} to={drill.activeHosts} />
              <StatTile value={o && o.inventory.databases} label="Databases" icon={<TileIcon kind="db" />} detail={o ? mix(o.inventory.databases_by_engine, (e) => engineName(e)) : undefined} to={drill.activeDatabases} />
              <StatTile value={o && o.inventory.applications} label="Applications" icon={<TileIcon kind="app" />} to={drill.activeApplications} />
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
          </section>

          <section className="dash-sec">
            <h2 className="stat-section">Needs attention</h2>
            <div className="stat-grid">
              <StatTile
                value={o && o.pending_requests}
                label="Pending approvals"
                icon={<TileIcon kind="approvals" />}
                detail={o?.in_flight && o.pending_requests > 0 && o.in_flight.oldest_pending_seconds > 0 ? `oldest waiting ${uptime(o.in_flight.oldest_pending_seconds)}` : undefined}
                to="/admin/approvals"
                tone="warn"
              />
              <StatTile value={attention} label="Hosts needing attention" icon={<TileIcon kind="attention" />} to={drill.hostsNeedingAttention} tone="warn" />
              <StatTile value={o && o.audit_24h.failed_logins} label="Failed sign-ins (24h)" icon={<TileIcon kind="key" />} to={drill.failedSignIns('/admin')} tone="warn" />
              <StatTile
                value={o && o.audit_24h.refused_connects}
                label="Refused connections (24h)"
                icon={<TileIcon kind="ban" />}
                trend={o?.trends && { days: o.trends.days, values: o.trends.refused, noun: 'refused connection' }}
                to={drill.refusedConnections('/admin')}
                tone="warn"
              />
            </div>
          </section>

          <section className="dash-sec">
            <h2 className="stat-section">Activity</h2>
            <div className="stat-grid">
              <StatTile value={o && o.sessions.open} label="Open sessions" icon={<TileIcon kind="session" />} to={drill.openSessions('/admin')} />
              <StatTile
                value={o?.in_flight ? o.in_flight.active : null}
                label="Grants active"
                icon={<TileIcon kind="key" />}
                detail={o?.in_flight && o.in_flight.ending_soon > 0 ? `${o.in_flight.ending_soon} end within the hour` : undefined}
                to="/admin/approvals"
              />
              <StatTile
                value={o && o.sessions.started_24h}
                label="Sessions (24h)"
                icon={<TileIcon kind="clock" />}
                trend={o?.trends && { days: o.trends.days, values: o.trends.sessions, noun: 'session' }}
                to={drill.sessions24h('/admin')}
              />
              <StatTile value={o && o.audit_24h.failures} label="Failures (24h)" icon={<TileIcon kind="attention" />} to={drill.failures('/admin')} />
            </div>
          </section>

          <section className="dash-sec">
            <h2 className="stat-section">Security posture</h2>
            <div className="stat-grid">
              <StatTile
                value={o?.posture ? o.posture.standing_no_mfa.grants : null}
                label="Standing access without MFA"
                icon={<TileIcon kind="shield" />}
                detail={o?.posture && o.posture.standing_no_mfa.grants > 0 ? `in ${o.posture.standing_no_mfa.policies} ${o.posture.standing_no_mfa.policies === 1 ? 'policy' : 'policies'}` : undefined}
                to="/admin/policies"
                tone="danger"
              />
              <StatTile value={o?.posture ? o.posture.not_enrolled : null} label="No authenticator yet" icon={<TileIcon kind="phone" />} to="/admin/users" tone="warn" />
              <StatTile value={o?.posture ? o.posture.dormant : null} label="Dormant (90 days)" icon={<TileIcon kind="moon" />} to="/admin/users" tone="warn" />
              <StatTile value={o?.posture ? o.posture.admins : null} label="Administrators" icon={<TileIcon kind="admin" />} to="/admin/users" />
            </div>
          </section>
        </div>
        <aside className="dash-side" aria-label="The gateway">
          {/* The heading first, as on the left, so the clock starts where the
              tiles do; the card stretches so Storage ends where they end. */}
          <h2 className="stat-section">Gateway</h2>
          <Clock skewMs={skew} />
          <div className="card dash-gw">
            {status === null ? (
              <p className="muted" style={{ margin: 0 }}>Loading…</p>
            ) : (
              <>
                {status.restart_required && (
                  <Alert tone="warn">The environment file changed; <Link to="/admin/settings">restart</Link> to apply it.</Alert>
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

          <section className="dash-sec">
            <h2 className="stat-section">Storage</h2>
            <div className="stat-grid">
              <StatTile
                value={o?.storage ? fmtBytes(o.storage.audit_log.approx_bytes) : null}
                label="Audit log"
                icon={<TileIcon kind="list" />}
                detail={o?.storage ? `${plural(o.storage.audit_log.events, 'event')}, size estimated` : undefined}
                to="/admin/events"
              />
              <StatTile
                value={o?.storage ? fmtBytes(o.storage.recordings.bytes) : null}
                label="Recordings"
                icon={<TileIcon kind="session" />}
                detail={o?.storage ? `${plural(o.storage.recordings.count, 'recording')} kept` : undefined}
                to="/admin/recordings"
              />
            </div>
          </section>
        </aside>
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

/** Gauge is one ratio against its limit: a label, the percentage first
 *  (2026-10-30: only CPU had one; a percentage reads at a glance), the
 *  figures behind it muted, and a meter whose fill escalates with the tone.
 *  Every gauge, now and later, gets the percentage by being a Gauge. */
function Gauge({ label, word, detail, fraction, tone, pct }: { label: string; word: string; detail?: ReactNode; fraction: number; tone?: 'warn' | 'danger'; pct?: number }) {
  const shown = pct ?? Math.round(Math.max(0, fraction) * 100)
  const fill = Math.round(Math.max(0, Math.min(1, fraction)) * 100)
  return (
    <div className="gauge">
      <div className="label">{label}</div>
      <div className="reading">
        <b className={'gauge-pct' + (tone ? ' ' + tone : '')}>{shown}%</b> {word}
        {detail && <span className="muted"> · {detail}</span>}
      </div>
      <div className={'meter' + (tone ? ' ' + tone : '')} role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={fill}>
        <i style={{ width: `${fill}%` }} />
      </div>
    </div>
  )
}

/** diskUse is df's Use%: used over used plus available, rounded up, so the
 *  blocks kept for root count as neither and the figure matches a terminal. */
function diskUse(d: { total_bytes: number; free_bytes: number; used_bytes?: number }): { pct: number; fraction: number } {
  const used = d.used_bytes ?? d.total_bytes - d.free_bytes
  const base = used + d.free_bytes
  if (base <= 0) return { pct: 0, fraction: 0 }
  return { pct: Math.ceil((used / base) * 100), fraction: used / base }
}

/** capTone escalates a count against its cap: at the cap the gateway
 *  refuses the next session, so that is danger; four fifths is the warning. */
function capTone(n: number, cap: number): 'warn' | 'danger' | undefined {
  if (n >= cap) return 'danger'
  if (n >= cap * 0.8) return 'warn'
  return undefined
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

/** HostFacts is the gateway host right now: a gauge per ratio, then a line
 *  for the facts that are not ratios. Words carry every state the colour
 *  does. A kind of session with a cap is a gauge against it (2026-10-31);
 *  without one its count joins the line. */
function HostFacts({ m }: { m: SystemMetrics }) {
  const used = m.memory ? m.memory.total_bytes - m.memory.available_bytes : 0
  const apps = m.application_sessions ?? 0
  const caps = m.session_caps ?? { applications: 0, databases: 0 }
  const line: ReactNode[] = []
  if (caps.databases === 0) line.push(plural(m.database_sessions, 'database session'))
  if (caps.applications === 0 && m.application_sessions !== undefined) line.push(plural(apps, 'application session'))
  if (m.images_bytes !== undefined) line.push(`container images ${fmtBytes(m.images_bytes)}`)
  if (m.guacd) line.push(<>guacd {m.guacd.reachable ? 'reachable' : <Badge tone="danger">unreachable at {m.guacd.address}</Badge>}</>)
  return (
    <>
      <div className="gw-grid">
        {m.cpu && m.cpus > 0 ? (
          <Gauge
            label={`CPU (${m.cpus} cores)`}
            word="busy"
            detail={m.load && <>load {m.load.fifteen.toFixed(2)} over 15 min</>}
            fraction={m.cpu.percent / 100}
            tone={m.cpu.percent >= 95 ? 'danger' : m.cpu.percent >= 85 ? 'warn' : undefined}
          />
        ) : m.load && m.cpus > 0 ? (
          <Gauge
            label={`Load (${m.cpus} cores)`}
            word="load"
            detail={<>{m.load.one.toFixed(2)} now · {m.load.fifteen.toFixed(2)} over 15 min</>}
            fraction={m.load.one / m.cpus}
            tone={m.load.one >= m.cpus ? 'danger' : m.load.one >= m.cpus * 0.85 ? 'warn' : undefined}
          />
        ) : null}
        {m.memory && (
          <Gauge
            label="Memory"
            word="used"
            detail={<>{fmtBytes(used)} of {fmtBytes(m.memory.total_bytes)}</>}
            fraction={used / m.memory.total_bytes}
            tone={used >= m.memory.total_bytes * 0.95 ? 'danger' : used >= m.memory.total_bytes * 0.85 ? 'warn' : undefined}
          />
        )}
        {m.disks.map((d) => (
          <Gauge
            key={d.path}
            label={d.system ? 'System disk' : d.what === 'recordings' ? 'Recordings' : `${d.what[0].toUpperCase() + d.what.slice(1)} disk`}
            word="used"
            detail={
              <>
                {fmtBytes(d.free_bytes)} free of {fmtBytes(d.total_bytes)}
                {diskTone(d) && (
                  <>
                    {' '}
                    <StateIcon state={diskTone(d) as 'warn' | 'danger'} label={`Low space: ${fmtBytes(d.free_bytes)} free`} />
                  </>
                )}
              </>
            }
            pct={diskUse(d).pct}
            fraction={diskUse(d).fraction}
            // The meter's tone follows its own geometry (how full); the badge
            // alone carries the absolute under-5-GB floor, so a tiny volume
            // never shows an alarmed near-empty bar.
            tone={d.free_bytes < d.total_bytes / 20 ? 'danger' : d.free_bytes < d.total_bytes / 10 ? 'warn' : undefined}
          />
        ))}
        {caps.applications > 0 && (
          <Gauge
            label="Application sessions"
            word="of the cap"
            detail={<>{apps} of {caps.applications} open</>}
            fraction={apps / caps.applications}
            tone={capTone(apps, caps.applications)}
          />
        )}
        {caps.databases > 0 && (
          <Gauge
            label="Database sessions"
            word="of the cap"
            detail={<>{m.database_sessions} of {caps.databases} open</>}
            fraction={m.database_sessions / caps.databases}
            tone={capTone(m.database_sessions, caps.databases)}
          />
        )}
      </div>
      {line.length > 0 && (
        <p className="muted" style={{ margin: '12px 0 0' }}>
          {line.map((part, i) => (
            <Fragment key={i}>
              {i > 0 && ' · '}
              {/* The line opens with a capital, whichever fact comes first. */}
              {i === 0 && typeof part === 'string' ? part[0].toUpperCase() + part.slice(1) : part}
            </Fragment>
          ))}
        </p>
      )}
    </>
  )
}

/**
 * Clock is the gateway's time in the console's zone (2026-10-30), ticking
 * each second. It counts from the gateway's own clock (status.now), so a
 * browser whose clock runs off still shows the gateway's time. Not a live
 * region: it must not be read out every second.
 */
function Clock({ skewMs }: { skewMs: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const zone = consoleZone()
  const at = new Date(now + skewMs)
  return (
    <section className="card dash-clock" aria-label="Gateway time">
      <time className="clock-time" dateTime={at.toISOString()}>
        {at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: zone })}
      </time>
      <div className="clock-date">{at.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', timeZone: zone })}</div>
      <div className="clock-zone muted">
        {zone} · {zoneLabel(at.getTime(), zone)}
      </div>
    </section>
  )
}
