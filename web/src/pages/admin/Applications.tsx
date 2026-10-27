import { appTLS } from '../../api/format'
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
      lead="Web applications opened in an isolated browser beside the gateway; policies grant them under HTTP."
      addLabel="Add application"
      empty="No applications yet. Add one with its upstream address."
      columns={['Upstream', 'TLS', 'Tags']}
      cells={(t) => (
        <>
          <td className="mono">{t.app_upstream}</td>
          <td><StateIcon state={appTLS(t).verified ? 'ok' : 'warn'} label={'Upstream: ' + appTLS(t).label} /></td>
          <td><Tags tags={t.tags} /></td>
        </>
      )}
    />
  )
}
