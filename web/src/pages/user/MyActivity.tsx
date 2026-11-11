import { useEffect } from 'react'
import { api, query } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { AuditEvent, Page } from '../../api/types'
import { usePaged } from '../../components/paged'
import { Alert, Badge, Empty, Loading, LoadMore, PageHead } from '../../components/ui'
import { capitalize, describe } from '../audit/eventText'

/** One event of the person's own activity, as GET /me/activity gives it. */
export interface ActivityRow {
  id: number
  ts: string
  action: string
  outcome: 'success' | 'failure'
  /** Where it came from; blank when another person did it. */
  ip: string
  /** Who did it when it was not the person: a username, "gateway" or "deleted user". */
  by?: string
  object_type?: string
  object_name?: string
  details?: Record<string, unknown>
}

/** sentence says the row the way the Events page says an event. */
function sentence(a: ActivityRow): string {
  const ev = { action: a.action, outcome: a.outcome, object_type: a.object_type ?? '', object_name: a.object_name, details: a.details ?? {} } as AuditEvent
  return capitalize(describe(ev))
}

/**
 * MyActivity is a person's own activity (2026-11-03, idea 11): their
 * sign-ins, failed ones too and from where, their sessions and requests, and
 * what an administrator or the gateway did to their account. Someone who
 * sees a sign-in they did not make knows to tell an administrator.
 */
export function MyActivity() {
  const { items, next, err, busy, load, more } = usePaged((cursor) => api.get<Page<ActivityRow>>('/me/activity' + query({ cursor, limit: 50 })))

  useEffect(() => {
    void load()
  }, [load])

  return (
    <>
      <PageHead title="Activity" />
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Loading />
        ) : items.length === 0 ? (
          <Empty>Nothing yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>What</th>
                <th>By</th>
                <th>From</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => {
                const what = sentence(a)
                // Most sentences say a failure in words already; the badge
                // is for those that do not.
                const badge = a.outcome === 'failure' && !/^(failed|was refused)/i.test(what)
                return (
                <tr key={a.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtTime(a.ts)}</td>
                  <td>
                    {what} {badge && <Badge tone="danger">failed</Badge>}
                  </td>
                  <td>{a.by ? <strong>{a.by}</strong> : <span className="muted">you</span>}</td>
                  <td className="mono muted">{a.ip || '—'}</td>
                </tr>
                )
              })}
            </tbody>
          </table>
        )}
        <LoadMore next={next} busy={busy} onMore={more} />
      </div>
    </>
  )
}
