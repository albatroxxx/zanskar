import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime, protocolName } from '../../api/format'
import type { AccessRequest, Page } from '../../api/types'
import { useAuth } from '../../auth/AuthContext'
import { Alert, Loading, PageHead, StateBadge } from '../../components/ui'
import { ApprovalsQueue } from './ApprovalsQueue'
import { query, what, who } from './requests'

/** ApproverApprovals is the approver's portal (ADR 0049): the requests the
 *  grants name them for, to approve or deny; the grants they may revoke; and
 *  what they decided. */
export function ApproverApprovals() {
  const { user } = useAuth()
  const [tick, setTick] = useState(0)
  return (
    <>
      <PageHead title="Approvals" />
      <ApprovalsQueue scope="mine" badgePath="/approvals" meID={user?.id} onChange={() => setTick((t) => t + 1)} />
      <History tick={tick} />
    </>
  )
}

/** History lists the requests in the approver's scope that no longer wait
 *  and no longer run: decided, lapsed, withdrawn. It reads again after each
 *  decision made above. */
function History({ tick }: { tick: number }) {
  const [items, setItems] = useState<AccessRequest[] | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    api
      .get<Page<AccessRequest>>(query('mine'))
      .then((p) => {
        setItems(p.items.filter((r) => r.state !== 'pending' && r.state !== 'approved'))
        setErr('')
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [tick])
  return (
    <div className="card table-wrap">
      <h2>History</h2>
      {err ? (
        <Alert tone="danger">The history could not be loaded: {err}</Alert>
      ) : items === null ? (
        <Loading />
      ) : items.length === 0 ? (
        <p className="muted" style={{ margin: 0 }}>Nothing decided yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Decided</th>
              <th>User</th>
              <th>Target</th>
              <th>Protocol</th>
              <th>Outcome</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td className="muted">{fmtTime(r.decided_at || r.updated_at)}</td>
                <td>{who(r)}</td>
                <td><strong>{what(r)}</strong></td>
                <td>{protocolName(r.protocol)}</td>
                <td><StateBadge lifecycle="access_request" state={r.state} /></td>
                <td className="muted">{r.decision_note || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
