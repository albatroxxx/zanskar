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
  const [search, setSearch] = useState('')

  // Recordings are found through the sessions list, which already carries
  // the user and target names, and filtered to rows that have a recording.
  const load = (cursor?: string) => {
    return api
      .get<Page<Session>>('/sessions' + query({ cursor, limit: 100 }))
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

  const needle = search.trim().toLowerCase()
  const visible = (items ?? []).filter((s) => {
    if (!needle) return true
    return [s.username, s.target_name, s.protocol, s.asg_instance_id, s.end_reason].some((v) => (v ?? '').toLowerCase().includes(needle))
  })

  return (
    <>
      <PageHead title="Recordings" lead="Every session is recorded: the terminal transcript and the commands that were run, or the desktop stream. Playing one is logged with your name.">
        <input
          className="mono"
          style={{ padding: '7px 10px', border: '1px solid var(--line-strong)', borderRadius: 'var(--radius)', background: 'var(--bg-raised)', minWidth: 220 }}
          placeholder="filter by user, machine, protocol"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Filter recordings"
        />
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : visible.length === 0 ? (
          <Empty>{items.length === 0 ? 'No recordings yet.' : 'No recordings match.'}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>User</th>
                <th>Machine</th>
                <th>Protocol</th>
                <th>Duration</th>
                <th>Ended</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.map((s) => (
                <tr key={s.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(s.started_at)}</td>
                  <td title={s.user_id}>{s.username ? <strong>{s.username}</strong> : <span className="mono muted">{shortId(s.user_id)}…</span>}</td>
                  <td title={s.target_id ?? s.asg_instance_id}>{s.target_name ?? (s.asg_instance_id ? <span className="mono">{shortId(s.asg_instance_id)}…</span> : <span className="muted">—</span>)}</td>
                  <td>{s.protocol.toUpperCase()}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                  <td>
                    <Link className="btn sm" to={`/audit/recordings/${s.recording_id}`}>Review</Link>
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
