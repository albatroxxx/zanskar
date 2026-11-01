import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, query } from '../../api/client'
import { fmtDuration, fmtTime, protocolName } from '../../api/format'
import { sessionTarget } from '../../api/labels'
import type { Page, Session } from '../../api/types'
import { FilterChips } from '../../components/FilterChips'
import { usePaged } from '../../components/paged'
import { Alert, Empty, LoadMore, PageHead, reasonBadge } from '../../components/ui'

export function MySessions() {
  // open=1, from the Targets page's "Open sessions" (2026-10-30), narrows to
  // the sessions still open, the ones it counted.
  const [sp, setSp] = useSearchParams()
  const openOnly = sp.get('open') === '1'
  const { items, next, err, busy, load, more } = usePaged((cursor) =>
    api.get<Page<Session>>('/me/sessions' + query({ open: openOnly ? 'true' : undefined, cursor, limit: 50 })),
  )

  useEffect(() => {
    void load()
  }, [load, openOnly])

  return (
    <>
      <PageHead title="Sessions" lead="Sessions are recorded." />
      {err && <Alert tone="danger">{err}</Alert>}
      <FilterChips chips={openOnly ? [{ label: 'Open only', onClear: () => setSp(new URLSearchParams(), { replace: true }) }] : []} />
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>{openOnly ? 'No open sessions.' : 'No sessions yet.'}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Target</th>
                <th>Protocol</th>
                <th>Duration</th>
                <th>Ended</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>{fmtTime(s.started_at)}</td>
                  <td title={s.target_id ?? s.asg_instance_id}>{sessionTarget(s)}</td>
                  <td>{protocolName(s.protocol)}</td>
                  <td>{fmtDuration(s.started_at, s.ended_at)}</td>
                  <td>{reasonBadge(s.end_reason)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <LoadMore next={next} busy={busy} onMore={more} />
      </div>
    </>
  )
}
