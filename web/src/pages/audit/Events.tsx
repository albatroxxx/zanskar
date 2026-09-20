import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage, query } from '../../api/client'
import { fmtTime, shortId } from '../../api/format'
import type { AuditEvent, AuditVerify, Page } from '../../api/types'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'

interface Filters { actor_user_id: string; action: string; object_type: string; from: string; to: string }
const emptyFilters: Filters = { actor_user_id: '', action: '', object_type: '', from: '', to: '' }

/** toRFC3339 converts a datetime-local value (browser local time) to UTC RFC 3339. */
function toRFC3339(local: string): string {
  if (!local) return ''
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}

function ChainStatus({ verify, err }: { verify: AuditVerify | null; err: string }) {
  if (err) return <Badge tone="danger">chain check failed: {err}</Badge>
  if (!verify) return <Badge>checking chain…</Badge>
  if (verify.intact) return <Badge tone="ok">chain intact · {verify.checked} events</Badge>
  return (
    <Badge tone="danger">
      CHAIN BROKEN at id {verify.broken?.ID ?? '?'}: {verify.broken?.Reason ?? 'unknown reason'}
    </Badge>
  )
}

function Details({ details }: { details: Record<string, unknown> }) {
  const [open, setOpen] = useState(false)
  const entries = Object.entries(details ?? {})
  if (entries.length === 0) return <span className="muted">—</span>
  const summary = entries
    .slice(0, 3)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(' ')
  return (
    <div>
      <span className="mono" style={{ wordBreak: 'break-all' }}>
        {summary.length > 80 ? summary.slice(0, 80) + '…' : summary}
      </span>{' '}
      <button className="btn sm ghost" onClick={() => setOpen(!open)}>
        {open ? 'hide' : 'show'}
      </button>
      {open && (
        <pre className="mono" style={{ margin: '6px 0 0', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxWidth: 520 }}>
          {JSON.stringify(details, null, 2)}
        </pre>
      )}
    </div>
  )
}

export function Events() {
  const [verify, setVerify] = useState<AuditVerify | null>(null)
  const [verifyErr, setVerifyErr] = useState('')
  const [draft, setDraft] = useState<Filters>(emptyFilters)
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [items, setItems] = useState<AuditEvent[] | null>(null)
  const [next, setNext] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api
      .get<AuditVerify>('/audit/verify')
      .then(setVerify)
      .catch((e) => setVerifyErr(errorMessage(e)))
  }, [])

  const load = useCallback(
    (f: Filters, cursor?: string) => {
      return api
        .get<Page<AuditEvent>>(
          '/audit/events' +
            query({
              actor_user_id: f.actor_user_id.trim(),
              action: f.action.trim(),
              object_type: f.object_type.trim(),
              from: toRFC3339(f.from),
              to: toRFC3339(f.to),
              cursor,
              limit: 50,
            }),
        )
        .then((p) => {
          setItems((cur) => (cursor && cur ? [...cur, ...p.items] : p.items))
          setNext(p.next_cursor ?? '')
        })
        .catch((e) => setErr(errorMessage(e)))
    },
    [],
  )

  useEffect(() => {
    void load(filters)
  }, [filters, load])

  const more = () => {
    setBusy(true)
    setErr('')
    void load(filters, next).finally(() => setBusy(false))
  }
  const apply = (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    setItems(null)
    setFilters({ ...draft })
  }
  const reset = () => {
    setErr('')
    setItems(null)
    setDraft(emptyFilters)
    setFilters(emptyFilters)
  }

  return (
    <>
      <PageHead title="Audit events" lead="Every sign-in, configuration change, session and recording view, hash-chained so nothing can be altered or removed unnoticed. Reading this page is itself recorded in the log.">
        <ChainStatus verify={verify} err={verifyErr} />
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}

      <form className="card" onSubmit={apply}>
        <div className="form-grid">
          <div className="field">
            <label htmlFor="f-actor">Actor user id</label>
            <input id="f-actor" value={draft.actor_user_id} onChange={(e) => setDraft({ ...draft, actor_user_id: e.target.value })} placeholder="user id" />
          </div>
          <div className="field">
            <label htmlFor="f-action">Action</label>
            <input id="f-action" value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })} placeholder="e.g. user.login" />
          </div>
          <div className="field">
            <label htmlFor="f-object">Object type</label>
            <input id="f-object" value={draft.object_type} onChange={(e) => setDraft({ ...draft, object_type: e.target.value })} placeholder="e.g. target" />
          </div>
          <div className="field">
            <label htmlFor="f-from">From</label>
            <input id="f-from" type="datetime-local" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="f-to">To</label>
            <input id="f-to" type="datetime-local" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />
          </div>
        </div>
        <div className="actions">
          <button className="btn primary" disabled={busy}>Apply filters</button>
          <button type="button" className="btn ghost" onClick={reset} disabled={busy}>Reset</button>
        </div>
      </form>

      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No events match.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>IP</th>
                <th>Action</th>
                <th>Object</th>
                <th>Outcome</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {items.map((ev) => (
                <tr key={ev.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(ev.ts)}</td>
                  <td className="mono" title={ev.actor_user_id}>{ev.actor_user_id ? shortId(ev.actor_user_id) : <span className="muted">—</span>}</td>
                  <td className="mono">{ev.actor_ip || <span className="muted">—</span>}</td>
                  <td className="mono">{ev.action}</td>
                  <td>
                    {ev.object_type ? (
                      <>
                        {ev.object_type}
                        {ev.object_id && (
                          <>
                            {' '}
                            <span className="mono muted" title={ev.object_id}>{shortId(ev.object_id)}</span>
                          </>
                        )}
                      </>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    <Badge tone={ev.outcome === 'success' ? 'ok' : 'danger'}>{ev.outcome}</Badge>
                  </td>
                  <td>
                    <Details details={ev.details} />
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
