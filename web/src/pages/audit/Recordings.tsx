import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage, query } from '../../api/client'
import { fmtDuration, fmtTime, shortId } from '../../api/format'
import type { Page, Session } from '../../api/types'
import { Alert, Empty, PageHead, reasonBadge } from '../../components/ui'

export function Recordings() {
  const [items, setItems] = useState<Session[] | null>(null)
  const [next, setNext] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  // The API has no recordings list endpoint yet; recordings are found
  // through the sessions list and filtered client-side to rows that
  // carry a recording_id. Pages therefore may show fewer than 50 rows.
  const load = (cursor?: string) => {
    return api
      .get<Page<Session>>('/sessions' + query({ cursor, limit: 50 }))
      .then((p) => {
        const withRec = p.items.filter((s) => !!s.recording_id)
        setItems((cur) => (cursor && cur ? [...cur, ...withRec] : withRec))
        setNext(p.next_cursor ?? '')
      })
      .catch((e) => setErr(errorMessage(e)))
  }

  useEffect(() => {
    void load()
  }, [])

  const more = () => {
    setBusy(true)
    void load(next).finally(() => setBusy(false))
  }

  return (
    <>
      <PageHead title="Recordings" lead="Every session is recorded. Playing a recording is logged with your name, the recording and the session it belongs to." />
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No recordings yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>User</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Duration</th>
                <th>Ended</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(s.started_at)}</td>
                  <td className="mono" title={s.user_id}>{shortId(s.user_id)}</td>
                  <td className="mono" title={s.target_id ?? s.asg_instance_id}>{shortId(s.target_id ?? s.asg_instance_id)}</td>
                  <td>{s.protocol}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                  <td>
                    <Link className="btn sm" to={`/audit/recordings/${s.recording_id}`}>Play</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {next && (
          <div className="actions" style={{ padding: 12 }}>
            <button className="btn sm" disabled={busy} onClick={more}>Load more</button>
          </div>
        )}
      </div>
    </>
  )
}
