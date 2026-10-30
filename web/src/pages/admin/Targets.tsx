import { fmtTime } from '../../api/format'
import { OSIcon } from '../../components/icons'
import { Badge, Tags } from '../../components/ui'
import { hostKeyIcon } from './lib'
import { TargetsPage } from './TargetsPage'

/** Targets lists hosts: machines reached over SSH, RDP, VNC or WinRM. Databases have their own page. */
export function Targets() {
  return (
    <TargetsPage
      kind="host"
      title="Hosts"
      addLabel="Add host"
      empty="No hosts yet."
      columns={['Address', 'OS', 'Capabilities', 'Host key', 'Tags', 'Last probed']}
      cells={(t) => (
        <>
          <td className="mono">{t.address}</td>
          <td><OSIcon os={t.os_family} /></td>
          <td>
            {t.capabilities.length === 0 ? <span className="muted">unprobed</span> : t.capabilities.map((c) => <Badge key={c} tone="accent">{c}</Badge>)}
          </td>
          <td>{hostKeyIcon(t.host_key_status)}</td>
          <td><Tags tags={t.tags} /></td>
          <td className="muted">{t.last_probed_at ? fmtTime(t.last_probed_at) : 'never'}</td>
        </>
      )}
    />
  )
}
