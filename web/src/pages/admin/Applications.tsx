import { useState } from 'react'
import { appTLS } from '../../api/format'
import type { Target } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Tags } from '../../components/ui'
import { TargetsPage } from './TargetsPage'

/**
 * Applications lists web applications opened in an isolated browser beside
 * the gateway (ADR 0034): each is one upstream origin the browser can reach,
 * streamed to the user like a desktop. Like databases they share the target
 * model with hosts and none of a host's notions, so they get their own page.
 */
export function Applications() {
  return (
    <TargetsPage
      kind="application"
      title="Applications"
      addLabel="Add application"
      empty="No applications yet."
      columns={['Upstream', 'TLS', 'Tags']}
      cells={(t) => (
        <>
          <UpstreamCell t={t} />
          <td><StateIcon state={appTLS(t).verified ? 'ok' : 'warn'} label={'Upstream: ' + appTLS(t).label} /></td>
          <td><Tags tags={t.tags} /></td>
        </>
      )}
    />
  )
}

/**
 * UpstreamCell is an application's upstream and, behind a toggle, every other
 * endpoint it reaches. The owner, 2026-11-11: "+1" in the list said there
 * were more and showed them only in a tooltip; the toggle lists them in the
 * row, name and address.
 */
function UpstreamCell({ t }: { t: Target }) {
  const [open, setOpen] = useState(false)
  const endpoints = t.app_endpoints ?? []
  const n = endpoints.length
  return (
    <td className="mono">
      {t.app_upstream}
      {n > 0 && (
        <button
          type="button"
          className="endpoints-toggle"
          aria-expanded={open}
          aria-label={`${open ? 'Hide' : 'Show'} ${n} other endpoint${n === 1 ? '' : 's'}`}
          onClick={() => setOpen((o) => !o)}
        >
          +{n} <span aria-hidden="true">{open ? '▴' : '▾'}</span>
        </button>
      )}
      {t.app_dependencies === 'origins' && <span className="muted" title="dependencies: its origins only"> · origins only</span>}
      {open && (
        <ul className="app-endpoints">
          {endpoints.map((e) => (
            <li key={e.url}>
              <span className="app-endpoint-name">{e.name}</span> {e.url}
            </li>
          ))}
        </ul>
      )}
    </td>
  )
}
