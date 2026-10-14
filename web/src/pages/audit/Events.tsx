import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage, query } from '../../api/client'
import { fmtPreciseTime, shortId } from '../../api/format'
import type { AuditEvent, AuditFacets, AuditVerify, Page } from '../../api/types'
import { usePaged } from '../../components/paged'
import { Alert, Badge, Empty, LoadMore, PageHead } from '../../components/ui'
import { capitalize, describe, detailText, humanAction, typeLabel, who, words } from './eventText'
import { useRecordingsPath } from './paths'

interface Filters { actor: string; action: string; object_type: string; range: string; from: string; to: string }
const emptyFilters: Filters = { actor: '', action: '', object_type: '', range: '', from: '', to: '' }

/** Time ranges offered instead of making a reviewer hand-type two timestamps.
 *  "Any time" is the default; the two pickers appear only for a custom range. */
const ranges: { key: string; label: string; hours?: number }[] = [
  { key: '', label: 'Any time' },
  { key: '1h', label: 'Last hour', hours: 1 },
  { key: '24h', label: 'Last 24 hours', hours: 24 },
  { key: '7d', label: 'Last 7 days', hours: 24 * 7 },
  { key: '30d', label: 'Last 30 days', hours: 24 * 30 },
  { key: 'custom', label: 'Custom range…' },
]

/** rangeBounds turns the chosen range into the from/to the API expects. */
function rangeBounds(f: Filters): { from: string; to: string } {
  if (f.range === 'custom') return { from: toRFC3339(f.from), to: toRFC3339(f.to) }
  const hours = ranges.find((r) => r.key === f.range)?.hours
  if (!hours) return { from: '', to: '' }
  return { from: new Date(Date.now() - hours * 3600_000).toISOString(), to: '' }
}

/** Routine events are hidden by default: the log's own reads, and the
 *  successful ticket issue that precedes every session (its refusals stay). */
const routine = 'audit.read,session.connect:success'

/** toRFC3339 converts a datetime-local value (browser local time) to UTC RFC 3339. */
function toRFC3339(local: string): string {
  if (!local) return ''
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}

/** DetailRow renders one key of an event's details for a reader: ids that
 *  the API could name show the name with the id behind a hover, a recording
 *  links to its player, nested values are shown compactly, and nothing is
 *  dropped, because this is the audit log. */
function DetailRow({ k, v, name }: { k: string; v: unknown; name?: string }) {
  const recordingsPath = useRecordingsPath()
  const id = typeof v === 'string' ? v : ''
  let body: React.ReactNode
  if (k === 'recording_id' && id) {
    body = <Link to={`${recordingsPath}/${id}`} title={id}>{name ?? 'play'}</Link>
  } else if (name) {
    body = <strong title={id}>{name}</strong>
  } else if (v === null || v === undefined || v === '') {
    body = <span className="muted">—</span>
  } else if (typeof v === 'object') {
    body = <code className="mono">{JSON.stringify(v)}</code>
  } else if (k.endsWith('_id') && id) {
    body = <span className="mono" title={id}>{shortId(id)}</span>
  } else {
    const d = detailText(v)
    body = <span title={d.title}>{d.text}</span>
  }
  return (
    <>
      <dt>{words(k)}</dt>
      <dd>{body}</dd>
    </>
  )
}

export function ChainStatus({ verify, err }: { verify: AuditVerify | null; err: string }) {
  if (err) return <Badge tone="danger">chain check failed: {err}</Badge>
  if (!verify) return <Badge>checking chain…</Badge>
  const problems = verify.problems ?? []
  const warnings = verify.warnings ?? []
  if (verify.intact) {
    const anchor = verify.last_anchor
      ? `The newest signed anchor covers event ${verify.last_anchor.event_id}, written ${fmtPreciseTime(verify.last_anchor.created_at)}.`
      : 'No signed anchor yet; the gateway writes one at start and every hour.'
    return (
      <span title={[anchor, ...warnings].join('\n')}>
        <Badge tone={warnings.length ? 'warn' : 'ok'}>
          chain intact · {verify.checked} events{warnings.length ? ` · ${warnings.length} warning${warnings.length > 1 ? 's' : ''}` : ''}
        </Badge>
      </span>
    )
  }
  if (!verify.broken && problems.length) {
    // The chain links, but a signed anchor or the id sequence shows events
    // were deleted or rewritten (ADR 0008).
    return (
      <span title={problems.join('\n')}>
        <Badge tone="danger">events deleted or edited: {problems[0]}</Badge>
      </span>
    )
  }
  return (
    <span title={['Every event is hashed onto the one before it. A break means a row was altered or removed after it was written, or was written by a build whose hashing differed.', ...problems].join('\n')}>
      <Badge tone="danger">chain broken at event {verify.broken?.ID ?? '?'}: {verify.broken?.Reason ?? 'unknown reason'}</Badge>
    </span>
  )
}

export function Events() {
  const [verify, setVerify] = useState<AuditVerify | null>(null)
  const [verifyErr, setVerifyErr] = useState('')
  const [facets, setFacets] = useState<AuditFacets>({ actions: [], object_types: [] })
  const [draft, setDraft] = useState<Filters>(emptyFilters)
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [showRoutine, setShowRoutine] = useState(false)
  const { items, next, err, setErr, busy, load, more, restart } = usePaged((cursor) =>
    api.get<Page<AuditEvent>>(
      '/audit/events' +
        query({
          actor: filters.actor.trim(),
          action: filters.action.trim(),
          object_type: filters.object_type.trim(),
          from: rangeBounds(filters).from,
          to: rangeBounds(filters).to,
          exclude: showRoutine ? '' : routine,
          cursor,
          limit: 50,
        }),
    ),
  )

  useEffect(() => {
    api
      .get<AuditVerify>('/audit/verify')
      .then(setVerify)
      .catch((e) => setVerifyErr(errorMessage(e)))
    // A filter that lists only what the log holds cannot offer a dead choice.
    // Failing to load them leaves the selects empty rather than the page broken.
    api
      .get<AuditFacets>('/audit/facets')
      .then((f) => setFacets({ actions: f.actions ?? [], object_types: f.object_types ?? [] }))
      .catch(() => setFacets({ actions: [], object_types: [] }))
  }, [])

  // Each change of filters reads the list again from its first page, and a
  // page still on its way for the old filters is dropped (B30).
  useEffect(() => {
    void load()
  }, [filters, showRoutine, load])

  const loadMore = () => {
    setErr('')
    more()
  }
  // The list empties the moment the filters change, and restart moves the
  // generation on here too: a page landing before the reload starts has
  // nowhere to go.
  const apply = (e: FormEvent) => {
    e.preventDefault()
    restart()
    setFilters({ ...draft })
  }
  const reset = () => {
    restart()
    setDraft(emptyFilters)
    // A new object, so the list is read again even when the filters were
    // empty already: restart has emptied it either way.
    setFilters({ ...emptyFilters })
  }
  const toggleRoutine = (on: boolean) => {
    restart()
    setShowRoutine(on)
  }

  // The password stage of a two-step sign-in is one line of a story whose
  // ending is the "signed in" event a second later; show it only on request.
  const visible = (items ?? []).filter((ev) => showRoutine || !(ev.action === 'user.login' && ev.outcome === 'success' && ev.details?.stage === 'password'))

  return (
    <>
      <PageHead title="Audit events" lead="Who signed in, who opened which machine, what changed, and who reviewed it. Every event is hash-chained so nothing can be altered or removed unnoticed; reading this page is itself recorded.">
        <ChainStatus verify={verify} err={verifyErr} />
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}

      <form className="card" onSubmit={apply}>
        <div className="form-grid">
          <div className="field">
            <label htmlFor="f-actor">User</label>
            <input id="f-actor" value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} placeholder="username" autoComplete="off" />
          </div>
          <div className="field">
            <label htmlFor="f-action">Action</label>
            <select id="f-action" value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })}>
              <option value="">Any action</option>
              {facets.actions.map((a) => (
                <option key={a} value={a}>{humanAction(a)}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-object">Object type</label>
            <select id="f-object" value={draft.object_type} onChange={(e) => setDraft({ ...draft, object_type: e.target.value })}>
              <option value="">Any object</option>
              {facets.object_types.map((t) => (
                <option key={t} value={t}>{typeLabel[t] ?? t}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-range">Time</label>
            <select id="f-range" value={draft.range} onChange={(e) => setDraft({ ...draft, range: e.target.value })}>
              {ranges.map((r) => (
                <option key={r.key} value={r.key}>{r.label}</option>
              ))}
            </select>
          </div>
          {draft.range === 'custom' && (
            <>
              <div className="field">
                <label htmlFor="f-from">From</label>
                <input id="f-from" type="datetime-local" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="f-to">To</label>
                <input id="f-to" type="datetime-local" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />
              </div>
            </>
          )}
        </div>
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>Apply filters</button>
          <button type="button" className="btn ghost" onClick={reset} disabled={busy}>Reset</button>
          <label className="field inline" style={{ margin: '0 0 0 auto' }}>
            <input type="checkbox" checked={showRoutine} onChange={(e) => toggleRoutine(e.target.checked)} />
            <span className="muted">Show routine events (audit reads, ticket issue, password stage)</span>
          </label>
        </div>
      </form>

      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : visible.length === 0 ? (
          <Empty>No events match.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Who</th>
                <th>What</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((ev) => {
                const w = who(ev)
                const raw = Object.keys(ev.details ?? {}).length > 0
                return (
                  <tr key={ev.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{fmtPreciseTime(ev.ts)}</td>
                    <td>
                      <div className="event-who">
                        <span className={'name' + (w.system ? ' muted' : '')} title={ev.actor_user_id || undefined}>{w.name}</span>
                        {ev.actor_ip && ev.actor_ip !== 'sync' && <span className="ip">{ev.actor_ip}</span>}
                      </div>
                    </td>
                    <td>
                      <div className="event-what">
                        <span>{describe(ev)}</span>
                        {/* The action code and object id are what an auditor
                            filters and correlates on, so they stay available
                            on hover (and in every export), but the row shows
                            names: an id fragment beside a name tells a reader
                            nothing. */}
                        <details>
                          <summary>details</summary>
                          <dl className="event-meta">
                            <dt>Action</dt>
                            <dd title={ev.action}>{humanAction(ev.action)}</dd>
                            {ev.object_id && (
                              <>
                                <dt>Object</dt>
                                <dd title={ev.object_id}>
                                  {capitalize(typeLabel[ev.object_type] ?? words(ev.object_type))}{' '}
                                  {ev.object_name ? <strong>{ev.object_name}</strong> : <span className="mono muted">{shortId(ev.object_id)}</span>}
                                </dd>
                              </>
                            )}
                            {Object.entries(ev.details ?? {}).map(([k, v]) => (
                              <DetailRow key={k} k={k} v={v} name={ev.details_names?.[k]} />
                            ))}
                          </dl>
                          {/* The stored JSON is the evidence; everything above is a
                              reading of it. Keep it one click away, never gone. */}
                          {raw && (
                            <details>
                              <summary>raw</summary>
                              <pre className="mono">{JSON.stringify(ev.details, null, 2)}</pre>
                            </details>
                          )}
                        </details>
                      </div>
                    </td>
                    <td>
                      <Badge tone={ev.outcome === 'success' ? 'ok' : 'danger'}>{ev.outcome}</Badge>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
        <LoadMore next={next} busy={busy} onMore={loadMore} />
      </div>
    </>
  )
}
