import { fmtTime, protocolName } from '../../api/format'
import { OSIcon } from '../../components/icons'
import { Badge, Tags } from '../../components/ui'
import { hostKeyIcon, usesHostKey } from './lib'
import { TargetsPage } from './TargetsPage'

/** Targets lists hosts: machines reached over SSH, RDP, VNC or WinRM. Databases have their own page. */
export function Targets() {
  return (
    <TargetsPage
      kind="host"
      title="Hosts"
      addLabel="Add host"
      empty="No hosts yet."
      columns={['Hostname or IP', 'OS', 'Capabilities', 'Host key', 'Tags', 'Last probed']}
      cells={(t) => (
        <>
          <td className="mono">{t.address}</td>
          <td><OSIcon os={t.os_family} /></td>
          <td>
            {t.capabilities.length === 0 ? <span className="muted">unprobed</span> : t.capabilities.map((c) => <Badge key={c} tone="accent">{protocolName(c)}</Badge>)}
          </td>
          <td>{usesHostKey(t) ? hostKeyIcon(t.host_key_status) : <span className="muted" title="No SSH on this host" aria-label="No SSH on this host">—</span>}</td>
          <td><Tags tags={t.tags} /></td>
          <td className="muted">{t.last_probed_at ? fmtTime(t.last_probed_at) : 'never'}</td>
        </>
      )}
    />
  )
}
