import type { Credential, Target } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Badge, Tags } from '../../components/ui'
import { TargetsPage } from './TargetsPage'

/**
 * Kubernetes lists the clusters (ADR 0045), Fabric's second tab (ADR 0048):
 * an API server enrolled once, reached through the gateway as the person.
 * Its Add button is Fabric's, so the page is passed `adding`.
 */
export function Kubernetes({ adding, setAdding }: { adding: boolean; setAdding: (v: boolean) => void }) {
  return (
    <TargetsPage
      kind="kubernetes"
      // The title names what the list holds (the search box and the empty match read it); Fabric shows the head.
      title="Clusters"
      addLabel="Add cluster"
      empty="No clusters yet."
      columns={['API server', 'Acts as', 'Credential', 'Tags']}
      cells={(t, credentials) => (
        <>
          <td className="mono">{t.kube_api_server}</td>
          <td>{t.kube_impersonate === false ? <Badge tone="warn">shared identity</Badge> : 'the person'}</td>
          <td>{credentialCell(t, credentials)}</td>
          <td><Tags tags={t.tags} /></td>
        </>
      )}
      adding={adding}
      setAdding={setAdding}
      headless
    />
  )
}

function credentialCell(t: Target, credentials: Credential[]) {
  const id = t.credentials.kube
  if (!id) return <StateIcon state="warn" label="No credential — cluster sessions cannot open" />
  const c = credentials.find((x) => x.id === id)
  return c ? <span>{c.name}</span> : <span className="muted">…</span>
}
