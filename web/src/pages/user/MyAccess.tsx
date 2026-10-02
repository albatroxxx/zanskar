import { useEffect, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { AccessRequest, AccessStatus, Page } from '../../api/types'
import { Alert, Badge, Empty, Field, Modal, PageHead } from '../../components/ui'

const tone: Record<AccessStatus, 'ok' | 'warn' | 'danger' | undefined> = {
  approved: 'ok',
  pending: 'warn',
  denied: 'danger',
  expired: undefined,
  revoked: undefined,
}

/** MyAccess lists the caller's just-in-time access requests and active grants (ADR 0018). */
export function MyAccess() {
  const [reqs, setReqs] = useState<AccessRequest[] | null>(null)
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')
  // Extend dialog: prefilled with the grant's own duration and reason; the
  // new request points at the grant and, once approved, runs on from it.
  const [extending, setExtending] = useState<AccessRequest | null>(null)
  const [ext, setExt] = useState({ minutes: 60, reason: '' })
  const [busy, setBusy] = useState(false)
  const [params, setParams] = useSearchParams()

  const load = () =>
    api
      .get<Page<AccessRequest>>('/me/access-requests')
      .then((p) => setReqs(p.items))
      .catch((e) => setErr(errorMessage(e)))

  useEffect(() => {
    void load()
  }, [])

  const now = Date.now()
  const active = (r: AccessRequest) => r.status === 'approved' && !!r.expires_at && new Date(r.expires_at).getTime() > now
  const openExtend = (r: AccessRequest) => {
    setExt({ minutes: r.approved_minutes || r.requested_minutes, reason: `Extension: ${r.reason}` })
    setExtending(r)
  }
  // The expiry notice links here with ?extend=<grant id>.
  useEffect(() => {
    const id = params.get('extend')
    if (!id || !reqs) return
    const r = reqs.find((x) => x.id === id)
    if (r && active(r)) openExtend(r)
    setParams({}, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reqs, params])

  const submitExtend = async (e: FormEvent) => {
    e.preventDefault()
    if (!extending) return
    setBusy(true)
    setErr('')
    try {
      await api.post<AccessRequest>('/me/access-requests', {
        target_id: extending.target_id,
        protocol: extending.protocol,
        reason: ext.reason,
        minutes: Number(ext.minutes),
        extends_request_id: extending.id,
      })
      setNotice(`Asked to extend ${extending.protocol.toUpperCase()} access to ${extending.target_name || extending.asg_name || 'the target'} by ${ext.minutes} minutes. An administrator must approve it; the current grant continues until it expires.`)
      setExtending(null)
      void load()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  // Names arrive with the request; the id is the last resort.
  const name = (r: AccessRequest) => r.target_name || r.asg_name || r.target_id || r.asg_id || '—'

  return (
    <>
      <PageHead title="My access" lead="Access you've requested to machines that require approval, and any grants currently active. Approved access lets you connect from Targets until it expires." />
      {err && <Alert tone="danger">{err}</Alert>}
      {notice && <Alert tone="ok">{notice}</Alert>}
      <div className="card table-wrap">
        {reqs === null ? (
          <Empty>Loading…</Empty>
        ) : reqs.length === 0 ? (
          <Empty>You haven't requested access to any approval-gated machines.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Reason</th>
                <th>Status</th>
                <th>Granted</th>
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reqs.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{fmtTime(r.created_at)}</td>
                  <td><strong>{name(r)}</strong></td>
                  <td>{r.protocol.toUpperCase()}</td>
                  <td>{r.reason}{r.extends_request_id && <> <Badge tone="warn">extension</Badge></>}{r.decision_note && <div className="muted">Note: {r.decision_note}</div>}</td>
                  <td><Badge tone={tone[r.status]}>{r.status}</Badge></td>
                  <td>{r.approved_minutes ? <>{r.approved_minutes} min{r.approved_minutes !== r.requested_minutes && <span className="muted"> (asked {r.requested_minutes})</span>}</> : <span className="muted">{r.requested_minutes} min asked</span>}</td>
                  <td className="muted">{r.status === 'approved' && r.expires_at ? fmtTime(r.expires_at) : '—'}</td>
                  <td>{active(r) && r.target_id && <button className="btn sm" onClick={() => openExtend(r)}>Extend…</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {extending && (
        <Modal title={`Extend access to ${name(extending)}`} onClose={() => setExtending(null)}>
          <p className="muted">Your current {extending.protocol.toUpperCase()} grant runs until {extending.expires_at ? fmtTime(extending.expires_at) : '—'}. If an administrator approves while this grant is still active, the extension starts when it ends, so there is no gap; approved after it has ended, the extension starts at approval.</p>
          <form onSubmit={(e) => void submitExtend(e)}>
            <Field label="Extend by (minutes)" hint="Capped by the policy">
              <input id="ext-minutes" type="number" min={1} value={ext.minutes} autoFocus onChange={(e) => setExt({ ...ext, minutes: Number(e.target.value) })} required />
            </Field>
            <Field label="Reason">
              <textarea id="ext-reason" value={ext.reason} onChange={(e) => setExt({ ...ext, reason: e.target.value })} required />
            </Field>
            <div className="actions">
              <button type="button" className="btn" onClick={() => setExtending(null)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy}>Request extension</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
