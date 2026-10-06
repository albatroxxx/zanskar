import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { fmtDuration, fmtTime } from '../../api/format'
import { sessionTarget, sessionUser } from '../../api/labels'
import type { Session } from '../../api/types'
import { Alert, Confirm, Empty, Field, PageHead, reasonBadge } from '../../components/ui'
import { useRecordingsPath } from '../audit/paths'
import { useList } from './lib'

// Mounted in the admin console and, without Terminate, in the audit portal,
// where an auditor watches live sessions read-only (ADR 0006).
export function Sessions() {
  const admin = useLocation().pathname.startsWith('/admin')
  const recordings = useRecordingsPath()
  const [openOnly, setOpenOnly] = useState(false)
  const [username, setUsername] = useState('')
  const [applied, setApplied] = useState('')
  const { items, err, setErr, reload } = useList<Session>('/sessions', { open: openOnly ? 'true' : undefined, username: applied || undefined })
  const [terminating, setTerminating] = useState<Session | null>(null)
  const [reason, setReason] = useState('')

  return (
    <>
      <PageHead
        title="Sessions"
        lead={
          admin
            ? "Every connection through the gateway. Terminating a live session closes the user's terminal immediately."
            : 'Every connection through the gateway. Watch a live session read-only; each view is audited.'
        }
      >
        <span className="field inline" style={{ margin: 0 }}>
          <input id="s-open" type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} />
          <label htmlFor="s-open">Live only</label>
        </span>
        <input id="s-user" placeholder="filter by username" value={username} onChange={(e) => setUsername(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setApplied(username.trim())} style={{ padding: '6px 10px', border: '1px solid var(--line-strong)', borderRadius: 6, background: 'var(--bg-raised)' }} />
        <button className="btn sm" onClick={() => setApplied(username.trim())}>Filter</button>
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
                  <td title={s.user_id}><strong>{sessionUser(s)}</strong></td>
                  <td title={s.target_id ?? s.asg_instance_id}>{sessionTarget(s)}</td>
                  <td>{s.protocol}</td>
                  <td className="mono muted">{s.client_ip}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                  <td>{s.recording_id ? <Link to={`${recordings}/${s.recording_id}`}>play</Link> : <span className="muted">—</span>}</td>
                  <td>
                    {!s.ended_at && (
                      <span className="actions">
                        <Link className="btn sm" to={`/audit/shadow/${s.id}?protocol=${s.protocol}&target=${encodeURIComponent(sessionTarget(s))}`} title="Watch live, read-only; the view is audited">
                          Watch
                        </Link>
                        {admin && (
                          <button className="btn sm danger" onClick={() => setTerminating(s)}>
                            Terminate
                          </button>
                        )}
                      </span>
                    )}
                  </td>
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
