import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { fmtDuration, fmtTime, shortId } from '../../api/format'
import type { Session } from '../../api/types'
import { Alert, Confirm, Empty, Field, PageHead, reasonBadge } from '../../components/ui'
import { useList } from './lib'

export function Sessions() {
  const [openOnly, setOpenOnly] = useState(false)
  const [userId, setUserId] = useState('')
  const [applied, setApplied] = useState('')
  const { items, err, setErr, reload } = useList<Session>('/sessions', { open: openOnly ? 'true' : undefined, user_id: applied || undefined })
  const [terminating, setTerminating] = useState<Session | null>(null)
  const [reason, setReason] = useState('')

  return (
    <>
      <PageHead title="Sessions" lead="Every connection through the gateway. Terminating a live session closes the user's terminal immediately.">
        <span className="field inline" style={{ margin: 0 }}>
          <input id="s-open" type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} />
          <label htmlFor="s-open">Live only</label>
        </span>
        <input id="s-user" placeholder="filter by user id" value={userId} onChange={(e) => setUserId(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setApplied(userId.trim())} style={{ padding: '6px 10px', border: '1px solid var(--line-strong)', borderRadius: 6, background: 'var(--bg-raised)' }} />
        <button className="btn sm" onClick={() => setApplied(userId.trim())}>Filter</button>
        <button className="btn sm" onClick={() => void reload()}>Refresh</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No sessions match.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>User</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>From</th>
                <th>Duration</th>
                <th>Ended</th>
                <th>Recording</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>{fmtTime(s.started_at)}</td>
                  <td className="mono" title={s.user_id}>{shortId(s.user_id)}</td>
                  <td className="mono" title={s.target_id ?? s.asg_instance_id}>{shortId(s.target_id ?? s.asg_instance_id)}</td>
                  <td>{s.protocol}</td>
                  <td className="mono muted">{s.client_ip}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                  <td>{s.recording_id ? <Link to={`/audit/recordings/${s.recording_id}`}>play</Link> : <span className="muted">—</span>}</td>
                  <td>{!s.ended_at && <button className="btn sm danger" onClick={() => setTerminating(s)}>Terminate</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {terminating && (
        <Confirm
          title="Terminate this session?"
          body={
            <div>
              <p>The user's terminal closes now. The session is recorded as ended by an administrator.</p>
              <Field label="Reason (optional, recorded in the audit log)">
                <input id="s-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
              </Field>
            </div>
          }
          confirmLabel="Terminate"
          danger
          onClose={() => {
            setTerminating(null)
            setReason('')
          }}
          onConfirm={async () => {
            try {
              await api.post(`/sessions/${terminating.id}/terminate`, reason ? { reason } : {})
              void reload()
            } catch (e) {
              setErr(errorMessage(e))
              throw e
            }
          }}
        />
      )}
    </>
  )
}
