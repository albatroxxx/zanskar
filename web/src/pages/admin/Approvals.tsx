import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { AccessRequest, Page, Target, User } from '../../api/types'
import { Alert, Empty, PageHead } from '../../components/ui'

/** Approvals is the admin queue for just-in-time access requests (ADR 0018):
 *  approve or deny what's pending, and revoke grants that are still active. */
export function Approvals() {
  const [pending, setPending] = useState<AccessRequest[] | null>(null)
  const [active, setActive] = useState<AccessRequest[]>([])
  const [tname, setTname] = useState<Record<string, string>>({})
  const [uname, setUname] = useState<Record<string, string>>({})
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')

  const load = () => {
    api.get<Page<AccessRequest>>('/access-requests?status=pending').then((p) => setPending(p.items)).catch((e) => setErr(errorMessage(e)))
    api.get<Page<AccessRequest>>('/access-requests?status=approved').then((p) => setActive(p.items)).catch(() => {})
  }
  useEffect(() => {
    load()
    api.get<Page<Target>>('/targets').then((p) => setTname(Object.fromEntries(p.items.map((t) => [t.id, t.name])))).catch(() => {})
    api.get<Page<User>>('/users').then((p) => setUname(Object.fromEntries(p.items.map((u) => [u.id, u.username])))).catch(() => {})
  }, [])

  const act = async (id: string, action: 'approve' | 'deny' | 'revoke') => {
    setBusy(id)
    setErr('')
    try {
      await api.post(`/access-requests/${id}/${action}`, {})
      load()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }
  const who = (r: AccessRequest) => uname[r.user_id] ?? r.user_id
  const what = (r: AccessRequest) => {
    const id = r.target_id ?? r.asg_id ?? ''
    return tname[id] ?? id ?? '—'
  }

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
                  <td>{r.protocol.toUpperCase()}</td>
                  <td>{r.reason}</td>
                  <td>{r.requested_minutes} min</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="btn sm primary" disabled={busy === r.id} onClick={() => void act(r.id, 'approve')}>Approve</button>{' '}
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
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {active.map((r) => (
                <tr key={r.id}>
                  <td>{who(r)}</td>
                  <td><strong>{what(r)}</strong></td>
                  <td>{r.protocol.toUpperCase()}</td>
                  <td className="muted">{r.expires_at ? fmtTime(r.expires_at) : '—'}</td>
                  <td><button className="btn sm" disabled={busy === r.id} onClick={() => void act(r.id, 'revoke')}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
