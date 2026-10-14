import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import type { AuditOverview, AuditVerify } from '../../api/types'
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
      <PageHead title="Dashboard" lead="The last 24 hours at a glance. Each number opens the page it is counted from; reading those pages is itself audited." />
      {err && <Alert tone="danger">The overview could not be loaded: {err}</Alert>}

      <h2 className="stat-section">Worth a look</h2>
      <div className="stat-grid">
        <StatTile value={o && o.events_24h.failures} one="failure in the last 24 hours" many="failures in the last 24 hours" to="/audit/events" tone="warn" />
        <StatTile value={o && o.events_24h.failed_logins} one="failed sign-in in the last 24 hours" many="failed sign-ins in the last 24 hours" to="/audit/events" tone="warn" />
        <StatTile value={o && o.events_24h.refused_connects} one="refused connection in the last 24 hours" many="refused connections in the last 24 hours" to="/audit/events" tone="warn" />
        <StatTile value={o && o.sessions.open} one="session open now" many="sessions open now" to="/audit/sessions" />
      </div>

      <h2 className="stat-section">Activity</h2>
      <div className="stat-grid">
        <StatTile value={o && o.sessions.started_24h} one="session in the last 24 hours" many="sessions in the last 24 hours" to="/audit/sessions" />
        <StatTile value={o && o.events_24h.events} one="audit event in the last 24 hours" many="audit events in the last 24 hours" to="/audit/events" />
        <StatTile value={o && o.reviews_24h.recording_views} one="recording played in the last 24 hours" many="recordings played in the last 24 hours" to="/audit/recordings" />
        <StatTile value={o && o.reviews_24h.recording_downloads} one="recording downloaded in the last 24 hours" many="recordings downloaded in the last 24 hours" to="/audit/recordings" />
      </div>

      <h2 className="stat-section">Log integrity</h2>
      <div className="card">
        <p className="muted" style={{ marginTop: 0 }}>
          Every event is hashed onto the one before it and anchored with a signature, so edits and deletions show. The check walks the whole log.
        </p>
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
