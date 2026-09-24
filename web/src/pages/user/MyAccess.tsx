import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { AccessRequest, AccessStatus, Page, ReachableTarget } from '../../api/types'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'

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
  const [names, setNames] = useState<Record<string, string>>({})
  const [err, setErr] = useState('')

  useEffect(() => {
    api
      .get<Page<AccessRequest>>('/me/access-requests')
      .then((p) => setReqs(p.items))
      .catch((e) => setErr(errorMessage(e)))
    // Resolve target names from the reachable list; ids are all we store.
    api
      .get<Page<ReachableTarget>>('/me/targets')
      .then((p) => setNames(Object.fromEntries(p.items.map((t) => [t.id, t.name]))))
      .catch(() => {})
  }, [])

  const name = (r: AccessRequest) => {
    const id = r.target_id ?? r.asg_id ?? ''
    return names[id] ?? id ?? '—'
  }

  return (
    <>
      <PageHead title="My access" lead="Access you've requested to machines that require approval, and any grants currently active. Approved access lets you connect from Targets until it expires." />
      {err && <Alert tone="danger">{err}</Alert>}
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
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {reqs.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{fmtTime(r.created_at)}</td>
                  <td><strong>{name(r)}</strong></td>
                  <td>{r.protocol.toUpperCase()}</td>
                  <td>{r.reason}</td>
                  <td><Badge tone={tone[r.status]}>{r.status}</Badge></td>
                  <td className="muted">{r.status === 'approved' && r.expires_at ? fmtTime(r.expires_at) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
