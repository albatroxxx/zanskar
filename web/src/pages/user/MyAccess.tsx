import { useEffect, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { expiresSoon } from '../../api/drilldown'
import { fmtTime, protocolName } from '../../api/format'
import type { AccessRequest, Page } from '../../api/types'
import { FilterChips } from '../../components/FilterChips'
import { Alert, Badge, Confirm, Empty, Field, Loading, Modal, PageHead, StateBadge } from '../../components/ui'
import { badgesChanged } from '../../components/badges'

/** The two moves a requester may make themselves (ADR 0049): withdraw a
 *  request that waits, or end a grant that runs. Cancelling keeps the
 *  request with Keep, so the dialog does not offer Cancel twice. */
const moves = {
  cancel: { title: 'Cancel request?', label: 'Cancel request', dismiss: 'Keep', danger: false },
  end: { title: 'End access?', label: 'End access', dismiss: 'Cancel', danger: true },
} as const

/** MyAccess lists the caller's just-in-time access requests and active grants (ADR 0018). */
export function MyAccess() {
  const [reqs, setReqs] = useState<AccessRequest[] | null>(null)
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')
  // Extend dialog: prefilled with the grant's own duration and reason; the
  // new request points at the grant and, once approved, runs on from it.
  const [extending, setExtending] = useState<AccessRequest | null>(null)
  const [ext, setExt] = useState({ minutes: 60, reason: '' })
  const [busy, setBusy] = useState(false)
  // A cancel or an end waits for a word, then posts to its route.
  const [moving, setMoving] = useState<{ r: AccessRequest; move: keyof typeof moves } | null>(null)
  const [params, setParams] = useSearchParams()

  const load = () =>
    api
      .get<Page<AccessRequest>>('/me/access-requests')
      .then((p) => setReqs(p.items))
      .catch((e) => setErr(errorMessage(e)))

  useEffect(() => {
    void load()
  }, [])

  const now = Date.now()
  // The gateway's state is the word (ADR 0047): a grant is active while it
  // reads approved; one past its window reads expired.
  const active = (r: AccessRequest) => r.state === 'approved' && !!r.expires_at
  // show=pending or show=expiring, from the Targets page's strip
  // (2026-10-30), narrows to the requests it counted.
  const show = params.get('show') === 'pending' || params.get('show') === 'expiring' ? params.get('show') : null
  const shown = reqs?.filter((r) => (show === 'pending' ? r.state === 'pending' : show === 'expiring' ? active(r) && expiresSoon(r.expires_at, now) : true)) ?? null
  const openExtend = (r: AccessRequest) => {
    setExt({ minutes: r.approved_minutes || r.requested_minutes, reason: `Extension: ${r.reason}` })
    setExtending(r)
  }
  // The expiry notice links here with ?extend=<grant id>.
  useEffect(() => {
    const id = params.get('extend')
    if (!id || !reqs) return
    const r = reqs.find((x) => x.id === id)
    if (r && active(r)) openExtend(r)
    setParams({}, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reqs, params])

  const submitExtend = async (e: FormEvent) => {
    e.preventDefault()
    if (!extending) return
    setBusy(true)
    setErr('')
    try {
      await api.post<AccessRequest>('/me/access-requests', {
        target_id: extending.target_id,
        asg_id: extending.asg_id,
        protocol: extending.protocol,
        reason: ext.reason,
        minutes: Number(ext.minutes),
        extends_request_id: extending.id,
      })
      badgesChanged()
      setNotice(`Asked to extend ${protocolName(extending.protocol)} access to ${extending.target_name || extending.asg_name || 'the target'} by ${ext.minutes} minutes.`)
      setExtending(null)
      void load()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  // Names arrive with the request; the id is the last resort.
  const name = (r: AccessRequest) => r.target_name || r.asg_name || r.target_id || r.asg_id || '—'

  return (
    <>
      <PageHead title="Access" />
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {notice && <Alert tone="ok" onDismiss={() => setNotice('')}>{notice}</Alert>}
      <FilterChips chips={show ? [{ label: show === 'pending' ? 'Pending' : 'Expiring within the hour', onClear: () => setParams({}, { replace: true }) }] : []} />
      <div className="card table-wrap">
        {shown === null ? (
          <Loading />
        ) : shown.length === 0 ? (
          <Empty>{show ? 'None right now.' : 'No requests yet.'}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Reason</th>
                <th>Status</th>
                <th>Granted</th>
                <th>Expires</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{fmtTime(r.created_at)}</td>
                  <td><strong>{name(r)}</strong></td>
                  <td>{protocolName(r.protocol)}</td>
                  <td>{r.reason}{r.extends_request_id && <> <Badge tone="warn">extension</Badge></>}{r.decision_note && <div className="muted">Note: {r.decision_note}</div>}</td>
                  <td><StateBadge lifecycle="access_request" state={r.state} /></td>
                  <td>{r.approved_minutes ? <>{r.approved_minutes} min{r.approved_minutes !== r.requested_minutes && <span className="muted"> (asked {r.requested_minutes})</span>}</> : <span className="muted">— (asked {r.requested_minutes})</span>}</td>
                  <td className="muted">{active(r) && r.expires_at ? fmtTime(r.expires_at) : '—'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {r.state === 'pending' && <button className="btn sm" onClick={() => setMoving({ r, move: 'cancel' })}>Cancel</button>}
                    {active(r) && (
                      <>
                        <button className="btn sm" onClick={() => openExtend(r)}>Extend…</button>{' '}
                        <button className="btn sm danger" onClick={() => setMoving({ r, move: 'end' })}>End</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {moving && (
        <Confirm
          title={moves[moving.move].title}
          body={<p className="muted">{protocolName(moving.r.protocol)} · {name(moving.r)}</p>}
          confirmLabel={moves[moving.move].label}
          dismissLabel={moves[moving.move].dismiss}
          danger={moves[moving.move].danger}
          onClose={() => setMoving(null)}
          onConfirm={async () => {
            await api.post(`/me/access-requests/${moving.r.id}/${moving.move}`, {})
            badgesChanged()
            void load()
          }}
        />
      )}

      {extending && (
        <Modal title={`Extend access to ${name(extending)}`} onClose={() => setExtending(null)}>
          <p className="muted">Your {protocolName(extending.protocol)} grant runs until {extending.expires_at ? fmtTime(extending.expires_at) : '—'}.</p>
          <form onSubmit={(e) => void submitExtend(e)}>
            <Field label="Extend by (minutes)" hint="Capped by the policy">
              <input id="ext-minutes" type="number" min={1} value={ext.minutes} autoFocus onChange={(e) => setExt({ ...ext, minutes: Number(e.target.value) })} required />
            </Field>
            <Field label="Reason">
              <textarea id="ext-reason" value={ext.reason} onChange={(e) => setExt({ ...ext, reason: e.target.value })} required />
            </Field>
            <div className="actions">
              <button type="button" className="btn" onClick={() => setExtending(null)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy}>Request extension</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
