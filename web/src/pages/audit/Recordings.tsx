import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, query } from '../../api/client'
import { fmtDuration, fmtTime } from '../../api/format'
import { sessionTarget, sessionUser } from '../../api/labels'
import type { Page, Session } from '../../api/types'
import { usePaged } from '../../components/paged'
import { Alert, Empty, LoadMore, PageHead, reasonBadge } from '../../components/ui'
import { useRecordingsPath } from './paths'

export function Recordings() {
  const recordingsPath = useRecordingsPath()
  // Recordings are found through the sessions list, which already carries
  // the user and target names, and filtered to rows that have a recording.
  const { items: sessions, next, err, busy, load, more } = usePaged((cursor) => api.get<Page<Session>>('/sessions' + query({ cursor, limit: 100 })))
  const items = sessions && sessions.filter((s) => !!s.recording_id)
  // How many sessions have been read so far, recorded or not.
  const scanned = sessions?.length ?? 0
  const [search, setSearch] = useState('')

  useEffect(() => {
    void load()
  }, [load])

  const needle = search.trim().toLowerCase()
  const visible = (items ?? []).filter((s) => {
    if (!needle) return true
    return [s.username, s.target_name, s.protocol, s.asg_instance_id, s.end_reason].some((v) => (v ?? '').toLowerCase().includes(needle))
  })
  // The API has no search, so the filter runs here over the sessions read so
  // far. While older ones are still unread, the page says how far back it has
  // looked instead of answering for sessions it has never seen.
  let nothing = items?.length === 0 ? 'No recordings yet.' : 'No recordings match.'
  if (next) {
    nothing = items?.length === 0
      ? `No recordings among the newest ${scanned} sessions. Load more to look further back.`
      : `No recordings among the newest ${scanned} sessions match. Load more to search further back.`
  }

  return (
    <>
      <PageHead title="Recordings" lead="Playing or downloading a recording is logged with your name.">
        <input
          className="mono filter-control"
          style={{ minWidth: 220 }}
          placeholder="filter by user, machine, protocol"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Filter recordings"
        />
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {next && visible.length > 0 && (
        <p className="muted">Showing recordings from the newest {scanned} sessions; the filter searches only these. Load more to go further back.</p>
      )}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>{err ? 'The recordings could not be listed.' : 'Loading…'}</Empty>
        ) : visible.length === 0 ? (
          <Empty>{nothing}</Empty>
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
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {visible.map((s) => (
                <tr key={s.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(s.started_at)}</td>
                  <td title={s.user_id}><strong>{sessionUser(s)}</strong></td>
                  <td title={s.target_id ?? s.asg_instance_id}>{sessionTarget(s)}</td>
                  <td>{s.protocol.toUpperCase()}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                  <td>
                    <Link className="btn sm" to={`${recordingsPath}/${encodeURIComponent(s.recording_id!)}`}>Review</Link>{' '}
                    {/* Downloads are recorded views and audit events, like playback. */}
                    <a className="btn sm ghost" href={`/api/v1/recordings/${encodeURIComponent(s.recording_id!)}/download`} download title="Download the recording file (audited)">Download</a>
                    {s.protocol !== 'rdp' && s.protocol !== 'vnc' && (
                      <>{' '}<a className="btn sm ghost" href={`/api/v1/recordings/${encodeURIComponent(s.recording_id!)}/transcript`} download title="Download the command lines as text (audited)">Transcript</a></>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <LoadMore next={next} busy={busy} onMore={more} />
      </div>
    </>
  )
}
