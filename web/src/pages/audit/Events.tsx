import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, errorMessage, query } from '../../api/client'
import { ranges, sinceFor } from '../../api/ranges'
import { consoleZone, fmtPreciseTime, shortId, zonedInputToISO } from '../../api/format'
import type { AuditEvent, AuditFacets, AuditVerify, Page } from '../../api/types'
import { usePaged } from '../../components/paged'
import { Alert, Badge, Empty, LoadMore, PageHead, TabLink } from '../../components/ui'
import { capitalize, describe, detailText, humanAction, typeLabel, who, words } from './eventText'
import { useRecordingsPath } from './paths'
import { StateIcon } from '../../components/icons'

interface Filters { actor: string; action: string; outcome: string; object_type: string; range: string; from: string; to: string }
const emptyFilters: Filters = { actor: '', action: '', outcome: '', object_type: '', range: '', from: '', to: '' }
const filterKeys = Object.keys(emptyFilters) as (keyof Filters)[]

/** The page's filters live in its address (2026-10-30), so a dashboard
 *  number opens exactly the events it counted, and Back, Forward and a shared
 *  link all show the same list. routine=1 shows the routine events too. */
function filtersFrom(sp: URLSearchParams): Filters {
  const f = { ...emptyFilters }
  for (const k of filterKeys) f[k] = sp.get(k) ?? ''
  if (f.outcome !== 'success' && f.outcome !== 'failure') f.outcome = ''
  return f
}

function paramsFrom(f: Filters, routine: boolean): URLSearchParams {
  const sp = new URLSearchParams()
  for (const k of filterKeys) {
    const v = f[k].trim()
    if (v && (f.range === 'custom' || (k !== 'from' && k !== 'to'))) sp.set(k, v)
  }
  if (routine) sp.set('routine', '1')
  return sp
}

/** The shared ranges, and a custom one with two pickers for the audit log. */
const eventRanges = [...ranges, { key: 'custom', label: 'Custom range…' }]

/** rangeBounds turns the chosen range into the from/to the API expects. */
function rangeBounds(f: Filters): { from: string; to: string } {
  if (f.range === 'custom') return { from: toRFC3339(f.from), to: toRFC3339(f.to) }
  return { from: sinceFor(f.range), to: '' }
}

/** Routine events are hidden by default: the log's own reads, and the
 *  successful ticket issue that precedes every session (its refusals stay). */
const routine = 'audit.read,session.connect:success'

/** toRFC3339 reads a datetime-local value in the console's time zone, the
 *  one the events are shown in, and returns it in UTC. */
function toRFC3339(local: string): string {
  return local ? zonedInputToISO(local) : ''
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
    body = <TabLink to={`${recordingsPath}/${id}`} title={id} label={name ?? 'play'} />
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
  const [sp, setSp] = useSearchParams()
  const spKey = sp.toString()
  const filters = useMemo(() => filtersFrom(new URLSearchParams(spKey)), [spKey])
  const showRoutine = new URLSearchParams(spKey).get('routine') === '1'
  const [draft, setDraft] = useState<Filters>(filters)
  // The form follows the address when it changes underneath it (a link, Back).
  useEffect(() => setDraft(filters), [filters])
  const { items, next, err, setErr, busy, load, more, restart } = usePaged((cursor) =>
    api.get<Page<AuditEvent>>(
      '/audit/events' +
        query({
          actor: filters.actor.trim(),
          action: filters.action.trim(),
          outcome: filters.outcome,
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
    const next = paramsFrom(draft, showRoutine)
    setSp(next, { replace: true })
    // Applying the filters already in place reads the list again.
    if (next.toString() === spKey) void load()
  }
  const reset = () => {
    restart()
    setDraft(emptyFilters)
    setSp(new URLSearchParams(), { replace: true })
    // The same address again reads nothing anew: read the list here.
    if (spKey === '') void load()
  }
  const toggleRoutine = (on: boolean) => {
    restart()
    setSp(paramsFrom(filters, on), { replace: true })
  }

  // The password stage of a two-step sign-in is one line of a story whose
  // ending is the "signed in" event a second later; show it only on request.
  const visible = (items ?? []).filter((ev) => showRoutine || !(ev.action === 'user.login' && ev.outcome === 'success' && ev.details?.stage === 'password'))

  return (
    <>
      <PageHead title="Audit events" lead="Viewing is logged.">
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
              {(facets.actions.includes(draft.action) || !draft.action ? facets.actions : [draft.action, ...facets.actions]).map((a) => (
                <option key={a} value={a}>{humanAction(a)}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-outcome">Outcome</label>
            <select id="f-outcome" value={draft.outcome} onChange={(e) => setDraft({ ...draft, outcome: e.target.value })}>
              <option value="">Any outcome</option>
              <option value="success">Succeeded</option>
              <option value="failure">Failed</option>
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
              {eventRanges.map((r) => (
                <option key={r.key} value={r.key}>{r.label}</option>
              ))}
            </select>
          </div>
          {draft.range === 'custom' && (
            <>
              <div className="field">
                <label htmlFor="f-from">
                  From <span className="muted">{consoleZone()}</span>
                </label>
                <input id="f-from" type="datetime-local" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="f-to">
                  To <span className="muted">{consoleZone()}</span>
                </label>
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
          err ? null : <Empty>Loading…</Empty>
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
                      <StateIcon state={ev.outcome === 'success' ? 'ok' : 'danger'} label={ev.outcome} />
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
