import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage, query } from '../../api/client'
import { fmtTime, shortId } from '../../api/format'
import type { AuditEvent, AuditFacets, AuditVerify, Page } from '../../api/types'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'

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

/** humanAction turns an action code into something readable while the code
 *  itself stays the value, so filtering still matches what the log stores. */
function humanAction(code: string): string {
  return code.replace(/[._]/g, ' ')
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

const typeLabel: Record<string, string> = {
  target: 'target',
  credential: 'credential',
  access_policy: 'policy',
  group: 'group',
  user: 'user',
  identity_provider: 'identity provider',
  autoscaling_group: 'autoscaling group',
  asg_instance: 'instance',
  access_session: 'session',
  session: 'session',
  recording: 'recording',
  audit_log: 'audit log',
}

const verbs: Record<string, string> = {
  create: 'created', update: 'updated', delete: 'deleted', probe: 'probed', sync: 'synced', rotate: 'rotated',
  set: 'set', unset: 'removed', trust: 'trusted', reset: 'reset', revoke: 'revoked', test: 'tested',
}

/** session splits "user → target (PROTO)" as the API labels sessions and recordings. */
function session(name?: string) {
  const m = /^(.+) → (.+) \((\w+)\)$/.exec(name ?? '')
  return m ? { user: m[1], target: m[2], proto: m[3] } : null
}

const str = (v: unknown) => (typeof v === 'string' ? v : '')
const words = (s: string) => s.replace(/_/g, ' ')

/** describe turns an event into the sentence a reviewer wants: who did what,
 *  to which named thing. It falls back to the raw action for anything unknown. */
function describe(ev: AuditEvent): string {
  const d = ev.details ?? {}
  const fail = ev.outcome === 'failure'
  const name = ev.object_name || (ev.object_id ? shortId(ev.object_id) : '')
  const s = session(ev.object_name)
  const proto = s?.proto ?? str(d.protocol).toUpperCase()
  const reason = str(d.reason)
  switch (ev.action) {
    case 'user.login':
      if (fail) return `failed to sign in${str(d.username) ? ` as ${str(d.username)}` : ''}${reason ? ` (${words(reason)})` : ''}`
      if (d.stage === 'password') return d.next === 'mfa_enrollment' ? 'entered a valid password; authenticator enrollment pending' : 'entered a valid password; second factor pending'
      return str(d.mfa) && d.mfa !== 'none' ? `signed in with ${str(d.mfa).toUpperCase()}` : 'signed in'
    case 'user.logout': return 'signed out'
    case 'user.mfa.enroll': return 'started enrolling an authenticator'
    case 'user.mfa.confirm': return fail ? 'failed to confirm an authenticator' : 'enrolled an authenticator'
    case 'user.mfa.verify': return fail ? 'failed the second factor' : 'passed the second factor'
    case 'session.connect': return fail ? `was refused ${proto} access to ${name}${reason ? ` (${words(reason)})` : ''}` : `requested ${proto} access to ${name}`
    case 'session.start': return s ? `opened a ${s.proto} session on ${s.target}` : `opened a session ${name}`
    case 'session.end': return s ? `ended the ${s.proto} session on ${s.target}${reason ? ` (${words(reason)})` : ''}` : `ended session ${name}`
    case 'session.terminate': return s ? `terminated ${s.user}'s ${s.proto} session on ${s.target}` : `terminated session ${name}`
    case 'session.shadow.start': return s ? `started watching ${s.user}'s ${s.proto} session on ${s.target}` : `started watching session ${name}`
    case 'session.shadow.end': return s ? `stopped watching ${s.user}'s session on ${s.target}` : `stopped watching session ${name}`
    case 'session.failover': return s ? `moved the ${s.proto} session on ${s.target} to another instance` : `failed over session ${name}`
    case 'recording.view': return s ? `played the recording of ${s.user} on ${s.target} (${s.proto})` : `played recording ${name}`
    case 'audit.read': return 'viewed the audit log'
    case 'target.hostkey.trust': return `trusted the host key of target ${name}`
    case 'target.hostkey.changed':
    case 'target.hostkey.mismatch': return `saw a changed host key on target ${name}`
    case 'target.tls.mismatch': return `saw a changed certificate on target ${name}`
    case 'target.credential.set': return `set a credential on target ${name}`
    case 'target.credential.unset': return `removed a credential from target ${name}`
    case 'asg.credential.set': return `set a credential on autoscaling group ${name}`
    case 'asg.credential.unset': return `removed a credential from autoscaling group ${name}`
    case 'asg.external_id.rotate': return `rotated the ExternalId of autoscaling group ${name}`
    case 'asg.instance.joined': return `instance ${name} joined autoscaling group ${str(d.name)}`
    case 'asg.instance.left': return `instance ${name} left autoscaling group ${str(d.name)}`
    case 'asg.instance.unhealthy': return `instance ${name} became unhealthy in autoscaling group ${str(d.name)}`
    case 'asg.instance.hostkey.changed':
    case 'asg.instance.hostkey.mismatch': return `saw a changed host key on instance ${name}`
    case 'group.members.update': return `updated the members of group ${name}`
    case 'user.roles.update': return `updated the roles of user ${name}`
    case 'user.password.reset': return `reset the password of user ${name}`
    case 'user.mfa.reset': return `reset the authenticator of user ${name}`
    case 'user.sessions.revoke': return `signed user ${name} out everywhere`
    default: {
      const parts = ev.action.split('.')
      const verb = verbs[parts[parts.length - 1]] ?? words(parts[parts.length - 1])
      const type = typeLabel[ev.object_type] ?? words(ev.object_type || parts[0])
      return `${fail ? 'failed to ' + (verbs[parts[parts.length - 1]] ? parts[parts.length - 1] : verb) : verb} ${type}${name ? ' ' + name : ''}`
    }
  }
}

function who(ev: AuditEvent): { name: string; system: boolean } {
  if (ev.actor_username) return { name: ev.actor_username, system: false }
  if (ev.actor_user_id) return { name: shortId(ev.actor_user_id) + '…', system: false }
  return { name: ev.actor_ip === 'sync' ? 'gateway' : 'system', system: true }
}

function ChainStatus({ verify, err }: { verify: AuditVerify | null; err: string }) {
  if (err) return <Badge tone="danger">chain check failed: {err}</Badge>
  if (!verify) return <Badge>checking chain…</Badge>
  if (verify.intact) return <Badge tone="ok">chain intact · {verify.checked} events</Badge>
  return (
    <span title="Every event is hashed onto the one before it. A break means a row was altered or removed after it was written, or was written by a build whose hashing differed.">
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
  const [items, setItems] = useState<AuditEvent[] | null>(null)
  const [next, setNext] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

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

  const load = useCallback((f: Filters, routineToo: boolean, cursor?: string) => {
    return api
      .get<Page<AuditEvent>>(
        '/audit/events' +
          query({
            actor: f.actor.trim(),
            action: f.action.trim(),
            object_type: f.object_type.trim(),
            from: rangeBounds(f).from,
            to: rangeBounds(f).to,
            exclude: routineToo ? '' : routine,
            cursor,
            limit: 50,
          }),
      )
      .then((p) => {
        setItems((cur) => (cursor && cur ? [...cur, ...p.items] : p.items))
        setNext(p.next_cursor ?? '')
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  useEffect(() => {
    void load(filters, showRoutine)
  }, [filters, showRoutine, load])

  const more = () => {
    setBusy(true)
    setErr('')
    void load(filters, showRoutine, next).finally(() => setBusy(false))
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
  const toggleRoutine = (on: boolean) => {
    setItems(null)
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
          <button className="btn primary" disabled={busy}>Apply filters</button>
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
                    <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(ev.ts)}</td>
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
                            filters and correlates on, so they stay available,
                            but they are internal identifiers: keeping them
                            inside the disclosure lets the row read as what
                            happened rather than as a method name. */}
                        <details>
                          <summary>details</summary>
                          <dl className="event-meta">
                            <dt>Action</dt>
                            <dd className="mono">{ev.action}</dd>
                            {ev.object_id && (
                              <>
                                <dt>Object</dt>
                                <dd className="mono">{typeLabel[ev.object_type] ?? ev.object_type} {shortId(ev.object_id)}</dd>
                              </>
                            )}
                          </dl>
                          {raw && <pre className="mono">{JSON.stringify(ev.details, null, 2)}</pre>}
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
        {next && (
          <div className="actions" style={{ padding: 12 }}>
            <button className="btn sm" disabled={busy} onClick={more}>Load more</button>
          </div>
        )}
      </div>
    </>
  )
}
