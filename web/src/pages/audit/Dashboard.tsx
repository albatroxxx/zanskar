import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import type { AuditOverview, AuditVerify } from '../../api/types'
import { TileIcon } from '../../components/icons'
import { drill } from '../../api/drilldown'
import { Alert, PageHead, StatTile } from '../../components/ui'
import { ChainStatus } from './Events'

/** Dashboard is where a review-only account lands (ADR 0029): what happened in
 *  the last day, what is live now, and whether the log itself is intact. The
 *  numbers are counts the server computes; anything that lists rows is on the
 *  pages behind the tiles, whose reads are audited. Checking the chain walks
 *  the whole log, so it runs from the button, never on load. */
export function Dashboard() {
  const [overview, setOverview] = useState<AuditOverview | null>(null)
  const [err, setErr] = useState('')
  const [verify, setVerify] = useState<AuditVerify | null>(null)
  const [verifyErr, setVerifyErr] = useState('')
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    api.get<AuditOverview>('/audit/overview').then(setOverview).catch((e) => setErr(errorMessage(e)))
  }, [])

  const check = () => {
    setChecking(true)
    setVerifyErr('')
    api
      .get<AuditVerify>('/audit/verify')
      .then(setVerify)
      .catch((e) => setVerifyErr(errorMessage(e)))
      .finally(() => setChecking(false))
  }

  const o = overview
  return (
    <>
      <PageHead title="Dashboard" />
      {err && <Alert tone="danger">The overview could not be loaded: {err}</Alert>}

      <h2 className="stat-section">Worth a look</h2>
      <div className="stat-grid">
        <StatTile value={o && o.events_24h.failures} label="Failures (24h)" icon={<TileIcon kind="attention" />} to={drill.failures('/audit')} tone="warn" />
        <StatTile value={o && o.events_24h.failed_logins} label="Failed sign-ins (24h)" icon={<TileIcon kind="key" />} to={drill.failedSignIns('/audit')} tone="warn" />
        <StatTile value={o && o.events_24h.refused_connects} label="Refused connections (24h)" icon={<TileIcon kind="ban" />} to={drill.refusedConnections('/audit')} tone="warn" />
        <StatTile value={o && o.sessions.open} label="Open sessions" icon={<TileIcon kind="session" />} to={drill.openSessions('/audit')} />
      </div>

      <h2 className="stat-section">Activity</h2>
      <div className="stat-grid">
        <StatTile value={o && o.sessions.started_24h} label="Sessions (24h)" icon={<TileIcon kind="clock" />} to={drill.sessions24h('/audit')} />
        <StatTile value={o && o.events_24h.events} label="Audit events (24h)" icon={<TileIcon kind="list" />} to={drill.auditEvents('/audit')} />
        <StatTile value={o && o.reviews_24h.recording_views} label="Recordings played (24h)" icon={<TileIcon kind="session" />} to={drill.recordingsPlayed('/audit')} />
        <StatTile value={o && o.reviews_24h.recording_downloads} label="Recordings downloaded (24h)" icon={<TileIcon kind="list" />} to={drill.recordingsDownloaded('/audit')} />
      </div>

      <h2 className="stat-section">Log integrity</h2>
      <div className="card">
        {(verify || verifyErr) && (
          <p style={{ margin: '0 0 12px' }}>
            <ChainStatus verify={verify} err={verifyErr} />
          </p>
        )}
        <button className="btn" onClick={check} disabled={checking}>
          {checking ? 'Checking…' : verify || verifyErr ? 'Check again' : 'Check the chain'}
        </button>
      </div>
    </>
  )
}
