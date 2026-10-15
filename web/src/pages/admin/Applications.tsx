import { appTLS } from '../../api/format'
import { StateIcon } from '../../components/icons'
import { Tags } from '../../components/ui'
import { TargetsPage } from './TargetsPage'

/**
 * Applications lists web applications served through the gateway's proxy
 * (ADR 0033): each is reached at its label under the apps domain and
 * forwarded to one upstream origin. Like databases they share the target
 * model with hosts and none of a host's notions, so they get their own page.
 */
export function Applications() {
  return (
    <TargetsPage
      kind="application"
      title="Applications"
      lead="Web applications served at their own address under the apps domain; policies grant them under HTTP."
      addLabel="Add application"
      empty="No applications yet. Set the apps domain and its certificate under Settings, then add one with its upstream address."
      columns={['Label', 'Upstream', 'TLS', 'Tags']}
      cells={(t) => (
        <>
          <td className="mono">{t.app_label}</td>
          <td className="mono">{t.app_upstream}</td>
          <td><StateIcon state={appTLS(t).verified ? 'ok' : 'warn'} label={'Upstream: ' + appTLS(t).label} /></td>
          <td><Tags tags={t.tags} /></td>
        </>
      )}
    />
  )
}
