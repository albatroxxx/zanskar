import { appTLS } from '../../api/format'
import type { Target } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Tags } from '../../components/ui'
import { EndpointList } from './TargetDetail'
import { TargetsPage, type RowDisclosure } from './TargetsPage'

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
      cells={(t, _credentials, row) => (
        <>
          <UpstreamCell t={t} row={row} />
          <td><StateIcon state={appTLS(t).verified ? 'ok' : 'warn'} label={'Upstream: ' + appTLS(t).label} /></td>
          <td><Tags tags={t.tags} /></td>
        </>
      )}
      detail={(t) => (t.app_endpoints?.length ? <EndpointList endpoints={t.app_endpoints} /> : null)}
    />
  )
}

/**
 * UpstreamCell is an application's upstream and, after it, Policies'
 * disclosure: a chevron that opens its other endpoints in a row beneath
 * (2026-11-12, after the owner found 1.19.2's "+1 ▾" pill wanting, and then
 * the count beside the chevron). The address stays outside the button so it
 * can still be selected and copied; the button's name carries the count and
 * aria-expanded says the state.
 */
function UpstreamCell({ t, row }: { t: Target; row: RowDisclosure }) {
  const n = t.app_endpoints?.length ?? 0
  return (
    <td className="mono">
      {t.app_upstream}
      {n > 0 && (
        <button
          type="button"
          className="expander inline"
          aria-expanded={row.open}
          aria-controls={row.detailId}
          aria-label={`${n} other endpoint${n === 1 ? '' : 's'}`}
          onClick={row.toggle}
        >
          <span className="chev" aria-hidden="true" />
        </button>
      )}
      {t.app_dependencies === 'origins' && <span className="muted" title="dependencies: its origins only"> · origins only</span>}
    </td>
  )
}
