import { useEffect, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import { api, errorMessage, query } from '../../api/client'
import { fmtDuration, fmtTime, protocolName } from '../../api/format'
import { ranges, sinceFor } from '../../api/ranges'
import { sessionTarget, sessionUser } from '../../api/labels'
import type { CloudActivity, Session } from '../../api/types'
import { recordingGone } from '../../api/states'
import { Alert, Confirm, Empty, Field, Loading, PageHead, EndReason, StateBadge, TabLink } from '../../components/ui'
import { useRecordingsPath } from '../audit/paths'
import { useList } from './lib'
import { SavedViews } from '../../components/SavedViews'

// Mounted in the admin console and, without Terminate, in the audit portal,
// where an auditor watches live sessions read-only (ADR 0006).
export function Sessions() {
  const admin = useLocation().pathname.startsWith('/admin')
  const recordings = useRecordingsPath()
  // The filters live in the address (2026-10-30): a dashboard's "Open
  // sessions" and "Sessions (24h)" open this list narrowed to what they
  // counted, and Back and a shared link keep it so.
  const [sp, setSp] = useSearchParams()
  const openOnly = sp.get('open') === '1'
  const range = ranges.some((r) => r.key === sp.get('range')) ? (sp.get('range') ?? '') : ''
  const applied = sp.get('user') ?? ''
  const [username, setUsername] = useState(applied)
  useEffect(() => setUsername(applied), [applied])
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(sp)
    if (value) next.set(key, value)
    else next.delete(key)
    setSp(next, { replace: true })
  }
  // The start of the range is fixed when the range is chosen, not at every
  // render, so the list is not read again each time the page draws.
  const [from, setFrom] = useState(() => sinceFor(range))
  useEffect(() => setFrom(sinceFor(range)), [range])
  const { items, err, setErr, reload } = useList<Session>('/sessions', { open: openOnly ? 'true' : undefined, username: applied || undefined, from: from || undefined })
  const [terminating, setTerminating] = useState<Session | null>(null)
  const [reason, setReason] = useState('')
  // When a cloud session's command line stops after a terminate asked now: its
  // credentials run on for up to fifteen minutes (ADR 0050). Fixed when the
  // dialog opens, not at every render.
  const [cliBy, setCliBy] = useState('')
  // A live cloud session's activity, read from CloudTrail on demand (ADR
  // 0050, phase C): the count of the last read stays beside the button.
  const [activity, setActivity] = useState<Record<string, string>>({})
  const [reading, setReading] = useState('')
  const readActivity = async (s: Session) => {
    setReading(s.id)
    try {
      const r = await api.post<CloudActivity>(`/sessions/${s.id}/activity`)
      setActivity((a) => ({ ...a, [s.id]: r.events === 0 ? 'none yet' : r.events === 1 ? '1 event' : `${r.events} events` }))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setReading('')
    }
  }

  return (
    <>
      <PageHead
        title="Sessions"
      >
        <span className="field inline" style={{ margin: 0 }}>
          <input id="s-open" type="checkbox" checked={openOnly} onChange={(e) => set('open', e.target.checked ? '1' : '')} />
          <label htmlFor="s-open">Live only</label>
        </span>
        <select id="s-range" className="filter-control" aria-label="Started" value={range} onChange={(e) => set('range', e.target.value)}>
          {ranges.map((r) => (
            <option key={r.key} value={r.key}>{r.key ? `Started: ${r.label.toLowerCase()}` : 'Started: any time'}</option>
          ))}
        </select>
        <input id="s-user" className="filter-control" placeholder="filter by username" aria-label="Filter by username" value={username} onChange={(e) => setUsername(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && set('user', username.trim())} />
        <button className="btn sm" onClick={() => set('user', username.trim())}>Filter</button>
        <button className="btn sm" onClick={() => (range ? setFrom(sinceFor(range)) : void reload())}>Refresh</button>
        <SavedViews page="sessions" current={sp.toString()} onOpen={(q) => setSp(new URLSearchParams(q), { replace: true })} />
        {/* Every session the filter matches, as CSV; the export is logged. */}
        <a className="btn sm" href={'/api/v1/sessions.csv' + query({ open: openOnly ? 'true' : undefined, username: applied || undefined, from: from || undefined })} download>CSV</a>
      </PageHead>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Loading />
        ) : items.length === 0 ? (
          <Empty>{applied || openOnly || range ? 'No sessions match.' : 'No sessions yet.'}</Empty>
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
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>{fmtTime(s.started_at)}</td>
                  <td title={s.user_id}><strong>{sessionUser(s)}</strong></td>
                  <td title={s.target_id ?? s.asg_instance_id}>{sessionTarget(s)}</td>
                  <td>{protocolName(s.protocol)}</td>
                  <td className="mono muted">{s.client_ip}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>
                    <EndReason state={s.state} reason={s.end_reason} detail={s.end_detail} />
                    {/* A cloud console sign-in runs on after the session ends (ADR 0050); the time is said. */}
                    {s.cloud_console_until && <div className="muted">Console until {fmtTime(s.cloud_console_until)}</div>}
                  </td>
                  <td>
                    {!s.recording_id ? (
                      <span className="muted">—</span>
                    ) : recordingGone(s.recording_state) ? (
                      <StateBadge lifecycle="recording" state={s.recording_state} />
                    ) : (
                      <TabLink className="btn sm" to={`${recordings}/${s.recording_id}`} label="Review" />
                    )}
                  </td>
                  <td>
                    {s.state === 'live' && (
                      <span className="actions">
                        <TabLink className="btn sm" to={`/audit/shadow/${s.id}?protocol=${s.protocol}&target=${encodeURIComponent(sessionTarget(s))}`} label="Watch" title="Watch live, read-only" />
                        {s.protocol === 'cloud' && (
                          <>
                            <button className="btn sm" disabled={reading === s.id} onClick={() => void readActivity(s)}>Activity</button>
                            {activity[s.id] && <span className="muted">{activity[s.id]}</span>}
                          </>
                        )}
                        {admin && (
                          <button className="btn sm danger" onClick={() => { setCliBy(new Date(Date.now() + 15 * 60_000).toISOString()); setTerminating(s) }}>
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
              {terminating.protocol === 'cloud' ? (
                // What a cloud session handed out runs on (ADR 0050): the command
                // line's credentials for up to fifteen minutes, the console to its
                // end. The two times, nothing else.
                <dl className="kv">
                  <dt>Command line</dt>
                  <dd>by {fmtTime(cliBy)}</dd>
                  {terminating.cloud_console_until && (
                    <>
                      <dt>Console</dt>
                      <dd>by {fmtTime(terminating.cloud_console_until)}</dd>
                    </>
                  )}
                </dl>
              ) : (
                /* Terminate ends the session, not the access (live, 2026-11-04: an
                   administrator expected the portal to go back to Request). */
                <p>
                  The session closes now; access stays.
                </p>
              )}
              <Field label="Reason (optional)">
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
