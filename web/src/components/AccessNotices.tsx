import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { fmtTime, protocolName } from '../api/format'
import type { AccessRequest, Page } from '../api/types'
import { Alert } from './ui'

const POLL_MS = 60_000
const SOON_MS = 10 * 60_000
const FRESH_MS = 24 * 60 * 60_000
const DISMISSED_KEY = 'zanskar.dismissed.access'

/** readDismissed and writeDismissed keep the dismissed notices' keys in the
 *  browser, the newest fifty, so a dismissal outlives the page. */
function readDismissed(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(DISMISSED_KEY) ?? '[]')
    return Array.isArray(v) ? v.filter((k): k is string => typeof k === 'string') : []
  } catch {
    return []
  }
}

function writeDismissed(keys: Set<string>) {
  try {
    localStorage.setItem(DISMISSED_KEY, JSON.stringify([...keys].slice(-50)))
  } catch {
    // Storage full or forbidden: the dismissal lasts the page, as before.
  }
}

/**
 * AccessNotices tells a user about their just-in-time requests without them
 * having to look: a request approved in the last day (with the minutes the
 * approver actually gave, which may differ from what was asked), one denied
 * in the last day (with the approver's note), and a grant that expires
 * within ten minutes, with a link to ask for an extension (manual QA
 * findings R16 and R17; denials 2026-11-03, later). Polled once a minute. A
 * notice stays until dismissed, and a dismissal is kept by the browser, so
 * a person away for eleven minutes still learns of a decision and is not
 * told twice (live, 2026-11-03: ten minutes and one page's life lost it).
 */
export function AccessNotices() {
  const [grants, setGrants] = useState<AccessRequest[]>([])
  const [dismissed, setDismissed] = useState<Set<string>>(() => new Set(readDismissed()))
  // Set by each poll rather than read during render, so a render is pure.
  const [now, setNow] = useState(0)

  useEffect(() => {
    const load = () =>
      api
        .get<Page<AccessRequest>>('/me/access-requests')
        .then((p) => {
          setGrants(p.items ?? [])
          setNow(Date.now())
        })
        .catch(() => {})
    void load()
    const t = setInterval(() => void load(), POLL_MS)
    return () => clearInterval(t)
  }, [])

  const dismiss = (key: string) =>
    setDismissed((d) => {
      const next = new Set(d).add(key)
      writeDismissed(next)
      return next
    })
  const what = (g: AccessRequest) => `${protocolName(g.protocol)} on ${g.target_name || g.asg_name || 'the target'}`
  const notices: { key: string; tone: 'ok' | 'warn' | 'danger'; body: React.ReactNode }[] = []
  for (const g of grants) {
    const decided = g.decided_at ? new Date(g.decided_at).getTime() : 0
    if (g.status === 'denied') {
      if (decided && now - decided < FRESH_MS && !dismissed.has('denied:' + g.id)) {
        notices.push({
          key: 'denied:' + g.id,
          tone: 'danger',
          body: <>Your request for {what(g)} was <strong>denied</strong>{g.decision_note ? <>: {g.decision_note}</> : null}.</>,
        })
      }
      continue
    }
    if (!g.expires_at || g.status !== 'approved') continue
    const expires = new Date(g.expires_at).getTime()
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
        body: <>Your access to {what(g)} ends in about <strong>{left} min</strong>. <Link to={`/access?extend=${g.id}`}>Ask to extend it</Link>.</>,
      })
    }
  }
  if (notices.length === 0) return null
  return (
    <div className="access-notices">
      {notices.map((n) => (
        <Alert key={n.key} tone={n.tone} onDismiss={() => dismiss(n.key)}>
          {n.body}
        </Alert>
      ))}
    </div>
  )
}
