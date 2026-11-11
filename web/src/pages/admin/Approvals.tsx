import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ApiError, api, errorMessage } from '../../api/client'
import { fmtTime, protocolName } from '../../api/format'
import type { AccessRequest, Page } from '../../api/types'
import { Alert, Badge, Field, Loading, Modal, PageHead } from '../../components/ui'
import { badgesChanged, shareBadgeCount } from '../../components/badges'

/** Approvals is the admin queue for just-in-time access requests (ADR 0018):
 *  approve or deny what's pending, and revoke grants that are still active. */
export function Approvals() {
  const [pending, setPending] = useState<AccessRequest[] | null>(null)
  const [active, setActive] = useState<AccessRequest[] | null>(null)
  // Why a list could not be read, shown in its place: a failed read must not
  // look like an empty queue, or an approver reads "nobody holds access".
  const [loadErr, setLoadErr] = useState({ pending: '', active: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  // The approve dialog: the approver may grant more or less than was asked,
  // inside the policy maximum, and leave a note the requester sees.
  const [approving, setApproving] = useState<AccessRequest | null>(null)
  const [grant, setGrant] = useState({ minutes: 0, note: '' })
  // Approving can ask for a recent authenticator code (2026-11-03, idea 3):
  // the gateway answers step_up_required, the dialog shows a code field,
  // and the next attempt proves the code first.
  const [needCode, setNeedCode] = useState(false)
  const [code, setCode] = useState('')
  const [approveErr, setApproveErr] = useState('')
  // A notification links to one request (?request=id): it opens at once
  // while it waits, and says what became of it when it no longer does.
  const [params] = useSearchParams()
  const linkedId = params.get('request') ?? ''
  const [linked, setLinked] = useState<{ request?: AccessRequest; err?: string } | null>(null)
  const openedLink = useRef('')

  const act = async (id: string, action: 'approve' | 'deny' | 'revoke', body: Record<string, unknown> = {}) => {
    setBusy(id)
    setErr('')
    try {
      await api.post(`/access-requests/${id}/${action}`, body)
      load()
      return true
    } catch (e) {
      setErr(errorMessage(e))
      // The request is no longer in the state the action needs (decided
      // elsewhere, or lapsed): the page reads again so it no longer offers it.
      if (e instanceof ApiError && e.status === 409) load()
      return false
    } finally {
      setBusy('')
      // A refusal (decided elsewhere meanwhile) changes the count as surely
      // as a decision does.
      badgesChanged()
    }
  }
  const openApprove = (r: AccessRequest) => {
    setGrant({ minutes: r.requested_minutes, note: '' })
    setNeedCode(false)
    setCode('')
    setApproveErr('')
    setApproving(r)
  }
  const approve = async (r: AccessRequest) => {
    setBusy(r.id)
    setApproveErr('')
    try {
      if (needCode) await api.post('/auth/mfa/step-up', { code: code.trim() })
      await api.post(`/access-requests/${r.id}/approve`, { minutes: grant.minutes, note: grant.note })
      setApproving(null)
      load()
    } catch (e) {
      if (e instanceof ApiError && e.code === 'step_up_required') {
        setNeedCode(true)
      } else {
        setApproveErr(errorMessage(e))
        if (e instanceof ApiError && e.status === 409) load()
      }
    } finally {
      setBusy('')
      badgesChanged()
    }
  }

  // The linked request, once, when the pending list first arrives: open it
  // while it waits; otherwise read it and say what became of it.
  function openLinked(items: AccessRequest[]) {
    if (!linkedId || openedLink.current === linkedId) return
    openedLink.current = linkedId
    const waiting = items.find((r) => r.id === linkedId)
    if (waiting) {
      openApprove(waiting)
      return
    }
    api
      .get<AccessRequest>(`/access-requests/${encodeURIComponent(linkedId)}`)
      .then((request) => setLinked({ request }))
      .catch((e) => setLinked({ err: e instanceof ApiError && e.status === 404 ? 'The request in the link was not found.' : errorMessage(e) }))
  }

  const load = () => {
    const read = (status: 'pending' | 'approved', list: 'pending' | 'active', set: (items: AccessRequest[]) => void) =>
      api
        .get<Page<AccessRequest>>(`/access-requests?status=${status}`)
        .then((p) => {
          // A grant whose window passed is expired whatever the row still
          // says; the gateway's state is the word (ADR 0047, 2026-11-09).
          set(list === 'active' ? p.items.filter((r) => r.state === 'approved') : p.items)
          setLoadErr((cur) => ({ ...cur, [list]: '' }))
          if (list === 'pending') {
            // The sidebar's badge counts these; it need not read them too.
            shareBadgeCount('/admin/approvals', p.items.length)
            openLinked(p.items)
          }
        })
        .catch((e) => setLoadErr((cur) => ({ ...cur, [list]: errorMessage(e) })))
    void read('pending', 'pending', setPending)
    void read('approved', 'active', setActive)
  }
  // Once, on arrival: decisions read again through load themselves.
  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  // The API resolves names at read time, for autoscaling groups too, and a
  // retired target still labels its old requests; the id is the last resort.
  const who = (r: AccessRequest) => r.username || r.user_id
  const what = (r: AccessRequest) => r.target_name || r.asg_name || r.target_id || r.asg_id || '—'

  return (
    <>
      <PageHead title="Approvals" />
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {linked?.err && <Alert tone="warn" onDismiss={() => setLinked(null)}>{linked.err}</Alert>}
      {linked?.request && <Alert onDismiss={() => setLinked(null)}>{decided(linked.request)}</Alert>}

      <div className="card table-wrap">
        <h2>Pending</h2>
        {loadErr.pending ? (
          <Alert tone="danger">The pending requests could not be loaded: {loadErr.pending}</Alert>
        ) : pending === null ? (
          <Loading />
        ) : pending.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>No requests are waiting.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>User</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Reason</th>
                <th>Duration</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {pending.map((r) => (
                <tr key={r.id} aria-current={r.id === linkedId ? 'true' : undefined}>
                  <td className="muted">{fmtTime(r.created_at)}</td>
                  <td>{who(r)}</td>
                  <td><strong>{what(r)}</strong></td>
                  <td>{protocolName(r.protocol)}</td>
                  <td>{r.reason}{r.extends_request_id && <> <Badge tone="warn">extension</Badge></>}</td>
                  <td>{r.requested_minutes} min</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="btn sm primary" disabled={busy === r.id} onClick={() => openApprove(r)}>Approve…</button>{' '}
                    <button className="btn sm danger" disabled={busy === r.id} onClick={() => void act(r.id, 'deny')}>Deny</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card table-wrap">
        <h2>Active grants</h2>
        {loadErr.active ? (
          <Alert tone="danger">The active grants could not be loaded: {loadErr.active}</Alert>
        ) : active === null ? (
          <Loading />
        ) : active.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>No active grants.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Granted</th>
                <th>Expires</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {active.map((r) => (
                <tr key={r.id}>
                  <td>{who(r)}</td>
                  <td><strong>{what(r)}</strong></td>
                  <td>{protocolName(r.protocol)}</td>
                  <td>{r.approved_minutes || r.requested_minutes} min{r.approved_minutes && r.approved_minutes !== r.requested_minutes ? <span className="muted"> (asked {r.requested_minutes})</span> : null}{r.extends_request_id && <> <Badge tone="warn">extension</Badge></>}</td>
                  <td className="muted">{r.expires_at ? fmtTime(r.expires_at) : '—'}</td>
                  <td><button className="btn sm" disabled={busy === r.id} onClick={() => void act(r.id, 'revoke')} title="Open sessions on the grant end">Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {approving && (
        <Modal title={`Approve ${who(approving)} on ${what(approving)}`} onClose={() => setApproving(null)}>
          <p className="muted">{protocolName(approving.protocol)} · asked for {approving.requested_minutes} minutes: “{approving.reason}”{approving.extends_request_id ? ' — an extension.' : ''}</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void approve(approving)
            }}
          >
            <Field label="Grant (minutes)" hint="Up to the policy maximum">
              <input id="ap-minutes" type="number" min={1} value={grant.minutes} autoFocus onChange={(e) => setGrant({ ...grant, minutes: Number(e.target.value) })} required />
            </Field>
            <Field label="Note (optional, shown to the requester)">
              <input id="ap-note" value={grant.note} onChange={(e) => setGrant({ ...grant, note: e.target.value })} />
            </Field>
            {needCode && (
              <Field label="Authenticator code">
                <input id="ap-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
              </Field>
            )}
            {approveErr && <Alert tone="danger">{approveErr}</Alert>}
            <div className="actions">
              <button type="button" className="btn" onClick={() => setApproving(null)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy === approving.id || grant.minutes < 1 || (needCode && !code.trim())}>Approve for {grant.minutes || '…'} min</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}

/** decided says what became of a linked request that no longer waits. */
function decided(r: AccessRequest): string {
  const whom = r.username || r.user_id
  const what = r.target_name || r.asg_name || r.target_id || r.asg_id || 'a target'
  const by = r.approver_username ? ` by ${r.approver_username}` : ''
  const when = r.decided_at ? ` ${fmtTime(r.decided_at)}` : ''
  switch (r.status) {
    case 'pending':
      return `${whom}'s request for ${what} waits below.`
    case 'approved':
      return `${whom}'s request for ${what} was already approved${by}${when}.`
    case 'denied':
      return `${whom}'s request for ${what} was already denied${by}${when}.`
    case 'revoked':
      return `${whom}'s grant on ${what} was revoked${when}.`
    default:
      return `${whom}'s request for ${what} has ${r.status}.`
  }
}
