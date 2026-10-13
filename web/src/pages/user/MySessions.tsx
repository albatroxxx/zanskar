import { useEffect } from 'react'
import { api, query } from '../../api/client'
import { fmtDuration, fmtTime } from '../../api/format'
import { sessionTarget } from '../../api/labels'
import type { Page, Session } from '../../api/types'
import { usePaged } from '../../components/paged'
import { Alert, Empty, LoadMore, PageHead, reasonBadge } from '../../components/ui'

export function MySessions() {
  const { items, next, err, load, more } = usePaged((cursor) => api.get<Page<Session>>('/me/sessions' + query({ cursor, limit: 50 })))

  useEffect(() => {
    void load()
  }, [load])

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
                  <td title={s.target_id ?? s.asg_instance_id}>{sessionTarget(s)}</td>
                  <td>{s.protocol}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <LoadMore next={next} onMore={more} />
      </div>
    </>
  )
}
