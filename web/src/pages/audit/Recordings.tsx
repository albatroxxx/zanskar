import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage, query } from '../../api/client'
import { fmtDuration, fmtTime, protocolName } from '../../api/format'
import { sessionTarget, sessionUser } from '../../api/labels'
import { recordingGone } from '../../api/states'
import type { Page, Session } from '../../api/types'
import { usePaged } from '../../components/paged'
import { Alert, Empty, LoadMore, PageHead, EndReason, TabLink } from '../../components/ui'
import { useRecordingsPath } from './paths'

/** A command line a search found (GET /recordings/search, ADR 0041). */
interface CommandHit {
  recording_id: string
  session_id: string
  username?: string
  target_name?: string
  protocol: string
  started_at: string
  seq: number
  at_ms: number
  command: string
}

/** A printed line a search found (GET /recordings/search?in=output). */
interface OutputHit {
  recording_id: string
  session_id: string
  username?: string
  target_name?: string
  protocol: string
  started_at: string
  at_ms: number
  line: string
  /** The last command typed before the line was printed. */
  after?: string
}

/** when is a hit's moment: its session's start plus its offset. */
const when = (h: { started_at: string; at_ms: number }) => fmtTime(new Date(Date.parse(h.started_at) + h.at_ms).toISOString())

/**
 * CommandSearch finds a command across every terminal recording still kept
 * (2026-11-03, idea 5): "who ran systemctl stop nginx?", or, in Output, what
 * a session printed: "where did bind() to 0.0.0.0:443 fail?". Each hit opens
 * the recording at that command or line. A search reads recordings' content
 * and is logged with its term.
 */
function CommandSearch({ recordingsPath }: { recordingsPath: string }) {
  const [q, setQ] = useState('')
  const [scope, setScope] = useState<'commands' | 'output'>('commands')
  const [hits, setHits] = useState<{ scope: 'commands'; items: CommandHit[] } | { scope: 'output'; items: OutputHit[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const search = async (e: FormEvent) => {
    e.preventDefault()
    if (q.trim().length < 2) return
    setBusy(true)
    setErr('')
    try {
      if (scope === 'output') {
        const r = await api.get<{ items: OutputHit[] }>('/recordings/search' + query({ q: q.trim(), in: 'output' }))
        setHits({ scope, items: r.items ?? [] })
      } else {
        const r = await api.get<{ items: CommandHit[] }>('/recordings/search' + query({ q: q.trim() }))
        setHits({ scope, items: r.items ?? [] })
      }
    } catch (e2) {
      setHits(null)
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="card">
      <form className="actions" onSubmit={search}>
        <select className="filter-control" aria-label="Search in" value={scope} onChange={(e) => setScope(e.target.value as 'commands' | 'output')}>
          <option value="commands">Commands</option>
          <option value="output">Output</option>
        </select>
        <input
          className="mono filter-control"
          style={{ minWidth: 280 }}
          placeholder={scope === 'output' ? 'find printed text, e.g. permission denied' : 'find a command, e.g. systemctl stop'}
          aria-label={scope === 'output' ? 'Find printed text' : 'Find a command'}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          maxLength={200}
        />
        <button type="submit" className="btn sm" disabled={busy || q.trim().length < 2}>{busy ? 'Searching…' : 'Find'}</button>
        <span className="muted">Terminal sessions.</span>
      </form>
      {err && <Alert tone="danger">{err}</Alert>}
      {hits?.scope === 'output' && (hits.items.length === 0 ? (
        <p className="muted">No output matches.</p>
      ) : (
        <table className="command-hits">
          <thead>
            <tr>
              <th>When</th>
              <th>User</th>
              <th>Machine</th>
              <th>Printed</th>
              <th><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {hits.items.map((h) => (
              <tr key={`${h.recording_id}:${h.at_ms}:${h.line}`}>
                <td style={{ whiteSpace: 'nowrap' }}>{when(h)}</td>
                <td>{h.username}</td>
                <td>{h.target_name}</td>
                <td>
                  <div className="mono">{h.line}</div>
                  {h.after && <div className="muted mono hit-after">after {h.after}</div>}
                </td>
                <td>
                  <TabLink className="btn sm" to={`${recordingsPath}/${encodeURIComponent(h.recording_id)}?at=${h.at_ms}`} label="Review" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
      {hits?.scope === 'commands' && (hits.items.length === 0 ? (
        <p className="muted">No command matches.</p>
      ) : (
        <table className="command-hits">
          <thead>
            <tr>
              <th>When</th>
              <th>User</th>
              <th>Machine</th>
              <th>Command</th>
              <th><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {hits.items.map((h) => (
              <tr key={`${h.recording_id}:${h.seq}`}>
                <td style={{ whiteSpace: 'nowrap' }}>{when(h)}</td>
                <td>{h.username}</td>
                <td>{h.target_name}</td>
                <td className="mono">{h.command}</td>
                <td>
                  <TabLink className="btn sm" to={`${recordingsPath}/${encodeURIComponent(h.recording_id)}?marker=${h.seq}`} label="Review" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  )
}

/** keptText says when retention deletes a recording, or that it has (Q10),
 *  or that its session ended with it unfinished (ADR 0047). */
function keptText(s: Session): string {
  if (s.recording_state === 'purged') return 'Deleted'
  if (s.recording_state === 'lost') return 'Lost'
  if (s.recording_kept_until) return fmtTime(s.recording_kept_until)
  if (!s.ended_at) return '—'
  return 'No age limit'
}

/** keptCell is keptText, muted unless it is a date. */
function keptCell(s: Session) {
  const text = keptText(s)
  return s.recording_kept_until && !['purged', 'lost'].includes(s.recording_state ?? '') ? text : <span className="muted">{text}</span>
}

/** rowText is what a row shows, in the words it shows them: the filter
 *  matches that. The owner asked what it filtered by (2026-11-11): it matched
 *  codes, so "user exit" found nothing where the row reads "user exit", and
 *  an autoscaling session matched an internal id, not the group or the
 *  instance on its row. */
function rowText(s: Session): string {
  const ended = s.state === 'live' ? 'live' : s.end_reason ? s.end_reason.replace(/_/g, ' ') : 'ended'
  return [fmtTime(s.started_at), sessionUser(s), sessionTarget(s), protocolName(s.protocol), ended, s.end_detail ?? '', keptText(s)].join('\n').toLowerCase()
}

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
  const visible = (items ?? []).filter((s) => !needle || rowText(s).includes(needle))
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
      <PageHead title="Recordings">
        <input
          className="mono filter-control"
          style={{ minWidth: 280 }}
          placeholder="user, machine, protocol, end…"
          title="Matches what the rows show: start, user, machine, protocol, how it ended, kept until"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Filter recordings"
        />
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <CommandSearch recordingsPath={recordingsPath} />
      {next && visible.length > 0 && (
        <p className="muted">Newest {scanned} sessions; the filter searches these.</p>
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
                <th>Kept until</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {visible.map((s) => (
                <tr key={s.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(s.started_at)}</td>
                  <td title={s.user_id}><strong>{sessionUser(s)}</strong></td>
                  <td title={s.target_id ?? s.asg_instance_id}>{sessionTarget(s)}</td>
                  <td>{protocolName(s.protocol)}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td><EndReason state={s.state} reason={s.end_reason} detail={s.end_detail} /></td>
                  <td style={{ whiteSpace: 'nowrap' }}>{keptCell(s)}</td>
                  <td>
                    {/* Review only (2026-11-01): the recording's page has its
                        downloads, the file and, for a terminal, the transcript.
                        None for a recording with no file left, which the
                        Kept until cell already says (2026-11-11). */}
                    {recordingGone(s.recording_state) ? (
                      <span className="muted">—</span>
                    ) : (
                      <TabLink className="btn sm" to={`${recordingsPath}/${encodeURIComponent(s.recording_id!)}`} label="Review" />
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
