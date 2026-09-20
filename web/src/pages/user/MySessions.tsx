import { useEffect, useState } from 'react'
import { api, errorMessage, query } from '../../api/client'
import { fmtDuration, fmtTime } from '../../api/format'
import type { Page, Session } from '../../api/types'
import { Alert, Empty, PageHead, reasonBadge } from '../../components/ui'

export function MySessions() {
  const [items, setItems] = useState<Session[] | null>(null)
  const [next, setNext] = useState('')
  const [err, setErr] = useState('')

  const load = (cursor?: string) =>
    api
      .get<Page<Session>>('/me/sessions' + query({ cursor, limit: 50 }))
      .then((p) => {
        setItems((cur) => (cursor && cur ? [...cur, ...p.items] : p.items))
        setNext(p.next_cursor ?? '')
      })
      .catch((e) => setErr(errorMessage(e)))

  useEffect(() => {
    void load()
  }, [])

  return (
    <>
      <PageHead title="My sessions" lead="When you connected and to what. Recordings are reviewed by auditors and administrators, not shown here." />
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No sessions yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Duration</th>
                <th>Ended</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>{fmtTime(s.started_at)}</td>
                  <td>{s.target_name ?? <span className="mono">{s.target_id ?? s.asg_instance_id}</span>}</td>
                  <td>{s.protocol}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {next && (
          <div className="actions" style={{ padding: 12 }}>
            <button className="btn sm" onClick={() => void load(next)}>Load more</button>
          </div>
        )}
      </div>
    </>
  )
}
