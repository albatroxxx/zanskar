import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../api/client'
import { fmtTime } from '../api/format'
import type { AccessRequest, Page } from '../api/types'

const POLL_MS = 30_000
/** From this close to its end, a grant shows its clock and the ask. */
const SOON_MS = 15 * 60_000

/** grantFor is the active approval grant a session runs on: the person's,
 *  for this target or group and protocol, the one ending last. */
export function grantFor(reqs: AccessRequest[], s: { target_id?: string; asg_id?: string; protocol: string }, now: number): AccessRequest | null {
  const mine = reqs.filter(
    (r) => r.status === 'approved' && r.protocol === s.protocol && !!r.expires_at && Date.parse(r.expires_at) > now &&
      ((s.asg_id && r.asg_id === s.asg_id) || (!s.asg_id && s.target_id && r.target_id === s.target_id)),
  )
  mine.sort((a, b) => Date.parse(b.expires_at!) - Date.parse(a.expires_at!))
  return mine[0] ?? null
}

function minutesLeft(until: string, now: number): number {
  return Math.max(0, Math.ceil((Date.parse(until) - now) / 60_000))
}

/**
 * GrantClock sits in a session's bar when the session runs on a just-in-time
 * grant that ends within 15 minutes (2026-11-03, idea 6): how long is left,
 * and Ask for more time, which sends the extension request the Access page
 * sends without leaving the session. An approved extension runs on from the
 * grant's end and the gateway keeps the session (ADR 0018); a session on
 * standing access shows nothing.
 */
export function GrantClock({ session }: { session: { target_id?: string; asg_id?: string; protocol: string } }) {
  const [reqs, setReqs] = useState<AccessRequest[]>([])
  const [now, setNow] = useState(0)
  const [asking, setAsking] = useState(false)
  const [minutes, setMinutes] = useState(60)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const load = useCallback(() => {
    api
      .get<Page<AccessRequest>>('/me/access')
      .then((p) => {
        setReqs(p.items ?? [])
        setNow(Date.now())
      })
      .catch(() => {})
  }, [])
  useEffect(() => {
    load()
    const t = setInterval(load, POLL_MS)
    return () => clearInterval(t)
  }, [load])

  const grant = now ? grantFor(reqs, session, now) : null
  if (!grant || Date.parse(grant.expires_at!) - now > SOON_MS) return null
  const pending = reqs.find((r) => r.status === 'pending' && r.extends_request_id === grant.id)
  const left = minutesLeft(grant.expires_at!, now)

  const ask = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await api.post('/me/access-requests', {
        target_id: grant.target_id,
        asg_id: grant.asg_id,
        protocol: grant.protocol,
        reason: reason.trim() || `Extension: ${grant.reason}`,
        minutes,
        extends_request_id: grant.id,
      })
      setAsking(false)
      load()
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  return (
    <span className="grant-clock" role="status">
      <span className={'stat' + (left <= 5 ? ' warn' : '')} title={`Access ends ${fmtTime(grant.expires_at!)}`}>
        access ends in {left} min
      </span>
      {pending ? (
        <span className="stat">more time asked; waiting for approval</span>
      ) : asking ? (
        <form className="grant-ask" onSubmit={ask}>
          <select aria-label="More minutes" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {[15, 30, 60, 120].map((m) => <option key={m} value={m}>{m} min</option>)}
          </select>
          <input aria-label="Why" placeholder="why" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
          <button type="submit" className="btn sm primary" disabled={busy}>Ask</button>
          <button type="button" className="btn sm" onClick={() => setAsking(false)}>Cancel</button>
          {err && <span className="stat warn">{err}</span>}
        </form>
      ) : (
        <button type="button" className="btn sm" onClick={() => setAsking(true)}>Ask for more time</button>
      )}
    </span>
  )
}
