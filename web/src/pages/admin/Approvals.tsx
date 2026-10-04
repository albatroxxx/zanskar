import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime, protocolName } from '../../api/format'
import type { AccessRequest, Page } from '../../api/types'
import { Alert, Badge, Empty, Field, Modal, PageHead } from '../../components/ui'

/** Approvals is the admin queue for just-in-time access requests (ADR 0018):
 *  approve or deny what's pending, and revoke grants that are still active. */
export function Approvals() {
  const [pending, setPending] = useState<AccessRequest[] | null>(null)
  const [active, setActive] = useState<AccessRequest[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  // The approve dialog: the approver may grant more or less than was asked,
  // inside the policy maximum, and leave a note the requester sees.
  const [approving, setApproving] = useState<AccessRequest | null>(null)
  const [grant, setGrant] = useState({ minutes: 0, note: '' })

  const load = () => {
    api.get<Page<AccessRequest>>('/access-requests?status=pending').then((p) => setPending(p.items)).catch((e) => setErr(errorMessage(e)))
    api.get<Page<AccessRequest>>('/access-requests?status=approved').then((p) => setActive(p.items)).catch(() => {})
  }
  useEffect(() => {
    load()
  }, [])

  const act = async (id: string, action: 'approve' | 'deny' | 'revoke', body: Record<string, unknown> = {}) => {
    setBusy(id)
    setErr('')
    try {
      await api.post(`/access-requests/${id}/${action}`, body)
      load()
      return true
    } catch (e) {
      setErr(errorMessage(e))
      return false
    } finally {
      setBusy('')
    }
  }
  const openApprove = (r: AccessRequest) => {
    setGrant({ minutes: r.requested_minutes, note: '' })
    setApproving(r)
  }
  // The API resolves names at read time, for autoscaling groups too, and a
  // retired target still labels its old requests; the id is the last resort.
  const who = (r: AccessRequest) => r.username || r.user_id
  const what = (r: AccessRequest) => r.target_name || r.asg_name || r.target_id || r.asg_id || '—'

  return (
    <>
      <PageHead title="Approvals" lead="Just-in-time access requests awaiting a decision, and the grants currently active. Approving grants time-bounded access; revoking ends an active grant early." />
      {err && <Alert tone="danger">{err}</Alert>}

      <div className="card table-wrap">
        <h2>Pending</h2>
        {pending === null ? (
          <Empty>Loading…</Empty>
        ) : pending.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>No requests are waiting.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>User</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Reason</th>
                <th>Duration</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {pending.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{fmtTime(r.created_at)}</td>
                  <td>{who(r)}</td>
                  <td><strong>{what(r)}</strong></td>
                  <td>{protocolName(r.protocol)}</td>
                  <td>{r.reason}{r.extends_request_id && <> <Badge tone="warn">extension</Badge></>}</td>
                  <td>{r.requested_minutes} min</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="btn sm primary" disabled={busy === r.id} onClick={() => openApprove(r)}>Approve…</button>{' '}
                    <button className="btn sm danger" disabled={busy === r.id} onClick={() => void act(r.id, 'deny')}>Deny</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card table-wrap">
        <h2>Active grants</h2>
        {active.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>No active grants.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Granted</th>
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {active.map((r) => (
                <tr key={r.id}>
                  <td>{who(r)}</td>
                  <td><strong>{what(r)}</strong></td>
                  <td>{protocolName(r.protocol)}</td>
                  <td>{r.approved_minutes || r.requested_minutes} min{r.approved_minutes && r.approved_minutes !== r.requested_minutes ? <span className="muted"> (asked {r.requested_minutes})</span> : null}{r.extends_request_id && <> <Badge tone="warn">extension</Badge></>}</td>
                  <td className="muted">{r.expires_at ? fmtTime(r.expires_at) : '—'}</td>
                  <td><button className="btn sm" disabled={busy === r.id} onClick={() => void act(r.id, 'revoke')}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {approving && (
        <Modal title={`Approve ${who(approving)} on ${what(approving)}`} onClose={() => setApproving(null)}>
          <p className="muted">{protocolName(approving.protocol)} · asked for {approving.requested_minutes} minutes: “{approving.reason}”{approving.extends_request_id ? ' — an extension: it runs on from the current grant while that is still active, otherwise from now.' : ''}</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void act(approving.id, 'approve', { minutes: grant.minutes, note: grant.note }).then((ok) => ok && setApproving(null))
            }}
          >
            <Field label="Grant (minutes)" hint="Any duration up to the policy maximum; the request keeps what was asked on record.">
              <input id="ap-minutes" type="number" min={1} value={grant.minutes} autoFocus onChange={(e) => setGrant({ ...grant, minutes: Number(e.target.value) })} required />
            </Field>
            <Field label="Note (optional, shown to the requester and recorded)">
              <input id="ap-note" value={grant.note} onChange={(e) => setGrant({ ...grant, note: e.target.value })} />
            </Field>
            <div className="actions">
              <button type="button" className="btn" onClick={() => setApproving(null)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy === approving.id || grant.minutes < 1}>Approve for {grant.minutes || '…'} min</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
