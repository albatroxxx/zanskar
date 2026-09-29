import { useEffect, useState } from 'react'
import { api, errorMessage, query } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { LogRecord, LogsPage } from '../../api/types'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'

const levels = ['debug', 'info', 'warn', 'error'] as const

function levelBadge(l: string) {
  const tone = l === 'ERROR' ? 'danger' : l === 'WARN' ? 'warn' : l === 'DEBUG' ? undefined : 'accent'
  return <Badge tone={tone}>{l.toLowerCase()}</Badge>
}

/**
 * Logs shows the gateway's most recent log records from memory (QA finding
 * R11): what journalctl would show, without shell access. The level filter
 * narrows what is shown; the runtime log.level setting decides what is
 * captured. Newest first; the download carries the whole ring.
 */
export function Logs() {
  const [level, setLevel] = useState<(typeof levels)[number]>('info')
  const [q, setQ] = useState('')
  const [applied, setApplied] = useState('')
  const [auto, setAuto] = useState(true)
  const [page, setPage] = useState<LogsPage | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let cancelled = false
    const load = () =>
      api
        .get<LogsPage>('/admin/logs' + query({ level, q: applied || undefined, limit: 500 }))
        .then((p) => {
          if (!cancelled) setPage(p)
        })
        .catch((e) => {
          if (!cancelled) setErr(errorMessage(e))
        })
    void load()
    if (!auto) return () => {
      cancelled = true
    }
    const t = setInterval(() => void load(), 5000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [level, applied, auto])

  return (
    <>
      <PageHead title="Logs" lead="The gateway's most recent log lines, from memory: what the journal shows, without shell access. The runtime log level (Settings) decides what is captured; raise it to debug to see more.">
        <select id="l-level" value={level} onChange={(e) => setLevel(e.target.value as (typeof levels)[number])} style={{ padding: '6px 10px', border: '1px solid var(--line-strong)', borderRadius: 6, background: 'var(--bg-raised)' }}>
          {levels.map((l) => (
            <option key={l} value={l}>{l} and above</option>
          ))}
        </select>
        <input id="l-q" placeholder="filter text" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setApplied(q.trim())} style={{ padding: '6px 10px', border: '1px solid var(--line-strong)', borderRadius: 6, background: 'var(--bg-raised)' }} />
        <button className="btn sm" onClick={() => setApplied(q.trim())}>Filter</button>
        <span className="field inline" style={{ margin: 0 }}>
          <input id="l-auto" type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
          <label htmlFor="l-auto">Follow</label>
        </span>
        <a className="btn sm" href="/api/v1/admin/logs/download" title="Every line in memory, oldest first, one JSON object per line; recorded in the audit log">Download</a>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {page && (
        <p className="muted">Showing {page.items.length} of the last {page.capacity} lines kept in memory ({page.seen} logged since start). Older lines are in the journal.</p>
      )}
      <div className="card table-wrap">
        {page === null ? (
          <Empty>Loading…</Empty>
        ) : page.items.length === 0 ? (
          <Empty>No log lines match.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Level</th>
                <th>Message</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((r: LogRecord, i) => (
                <tr key={r.time + i}>
                  <td className="muted" style={{ whiteSpace: 'nowrap' }}>{fmtTime(r.time)}</td>
                  <td>{levelBadge(r.level)}</td>
                  <td>{r.msg}</td>
                  <td className="mono muted" style={{ fontSize: '0.78rem' }}>
                    {Object.entries(r.attrs ?? {}).map(([k, v]) => (
                      <span key={k} style={{ marginRight: 10 }}>{k}={v}</span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
