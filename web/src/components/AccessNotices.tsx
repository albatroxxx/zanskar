import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { fmtTime } from '../api/format'
import type { AccessRequest, Page } from '../api/types'
import { Alert } from './ui'

const POLL_MS = 60_000
const SOON_MS = 10 * 60_000
const FRESH_MS = 10 * 60_000

/**
 * AccessNotices tells a user about their just-in-time grants without them
 * having to look: a grant approved in the last ten minutes (with the minutes
 * the approver actually gave, which may differ from what was asked), and a
 * grant that expires within ten minutes, with a link to ask for an extension
 * (manual QA findings R16 and R17). Polled once a minute; each notice can be
 * dismissed for the rest of the page's life.
 */
export function AccessNotices() {
  const [grants, setGrants] = useState<AccessRequest[]>([])
  const [dismissed, setDismissed] = useState<Set<string>>(new Set())
  // Set by each poll rather than read during render, so a render is pure.
  const [now, setNow] = useState(0)

  useEffect(() => {
    const load = () =>
      api
        .get<Page<AccessRequest>>('/me/access')
        .then((p) => {
          setGrants(p.items ?? [])
          setNow(Date.now())
        })
        .catch(() => {})
    void load()
    const t = setInterval(() => void load(), POLL_MS)
    return () => clearInterval(t)
  }, [])

  const dismiss = (key: string) => setDismissed((d) => new Set(d).add(key))
  const what = (g: AccessRequest) => `${g.protocol.toUpperCase()} on ${g.target_name || g.asg_name || 'the target'}`
  const notices: { key: string; tone: 'ok' | 'warn'; body: React.ReactNode }[] = []
  for (const g of grants) {
    if (!g.expires_at) continue
    const expires = new Date(g.expires_at).getTime()
    const decided = g.decided_at ? new Date(g.decided_at).getTime() : 0
    const minutes = g.approved_minutes || g.requested_minutes
    if (decided && now - decided < FRESH_MS && !dismissed.has('approved:' + g.id)) {
      notices.push({
        key: 'approved:' + g.id,
        tone: 'ok',
        body: <>{what(g)} was approved for <strong>{minutes} minutes</strong>{minutes !== g.requested_minutes ? ` (you asked for ${g.requested_minutes})` : ''}, until {fmtTime(g.expires_at)}.</>,
      })
    }
    if (expires - now < SOON_MS && expires > now && !dismissed.has('expiring:' + g.id)) {
      const left = Math.max(1, Math.round((expires - now) / 60_000))
      notices.push({
        key: 'expiring:' + g.id,
        tone: 'warn',
        body: <>Your access to {what(g)} ends in about <strong>{left} min</strong>. <Link to={`/access?extend=${g.id}`}>Ask to extend it</Link>; an administrator must approve.</>,
      })
    }
  }
  if (notices.length === 0) return null
  return (
    <div className="access-notices">
      {notices.map((n) => (
        <Alert key={n.key} tone={n.tone}>
          <span className="grow">{n.body}</span>
          <button className="btn sm ghost" onClick={() => dismiss(n.key)} aria-label="Dismiss">Dismiss</button>
        </Alert>
      ))}
    </div>
  )
}
