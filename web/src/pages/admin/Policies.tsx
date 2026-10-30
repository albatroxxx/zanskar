import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import type { AutoscalingGroup, Group, Policy, Target, User } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Alert, Badge, Confirm, Empty, PageHead } from '../../components/ui'
import { useList } from './lib'
import { grantSummary, whoSummary } from './policyModel'

/**
 * Policies lists the access policies (ADR 0036): who each applies to and one
 * line per grant. Adding and editing happen on a page of their own.
 */
export function Policies() {
  const { items, err, setErr, reload } = useList<Policy>('/access-policies')
  const groups = useList<Group>('/groups')
  const users = useList<User>('/users')
  const targets = useList<Target>('/targets', { limit: 500 })
  const asgs = useList<AutoscalingGroup>('/autoscaling-groups')
  const [deleting, setDeleting] = useState<Policy | null>(null)
  const groupName = (id: string) => groups.items?.find((g) => g.id === id)?.name ?? id.slice(0, 8)
  const userName = (id: string) => users.items?.find((u) => u.id === id)?.username ?? id.slice(0, 8)
  const nameOf = (id: string) => targets.items?.find((t) => t.id === id)?.name ?? asgs.items?.find((g) => g.id === id)?.name ?? id.slice(0, 8)

  return (
    <>
      <PageHead title="Access policies" lead="Standing access wins over approval; where grants overlap, each limit is the strictest.">
        <Link className="btn primary" to="/admin/policies/new">Add policy</Link>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No policies yet. Nobody can connect until a policy grants access.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Who</th>
                <th>Grants</th>
                <th>Enabled</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={p.id}>
                  <td>
                    <strong>{p.name}</strong>
                    {p.description && <div className="muted">{p.description}</div>}
                  </td>
                  <td>{p.subjects.length === 0 ? <Badge tone="warn">no one</Badge> : whoSummary(p, groupName, userName)}</td>
                  <td>
                    {p.grants.length === 0 ? (
                      <Badge tone="warn">no grants</Badge>
                    ) : (
                      p.grants.map((g, i) => <div key={g.id ?? i} className="grant-line">{grantSummary(g, nameOf)}</div>)
                    )}
                  </td>
                  <td>{p.enabled ? <StateIcon state="ok" label="Enabled" /> : <StateIcon state="unknown" label="Disabled" />}</td>
                  <td className="actions">
                    <Link className="btn sm" to={`/admin/policies/${p.id}`}>Edit</Link>
                    <button className="btn sm danger" onClick={() => setDeleting(p)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {deleting && (
        <Confirm
          title={`Delete policy ${deleting.name}?`}
          body="Its people lose this access; their live sessions are re-checked and end if nothing else admits them."
          confirmLabel="Delete"
          danger
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            try {
              await api.del(`/access-policies/${deleting.id}`)
              void reload()
            } catch (e) {
              setErr(errorMessage(e))
              throw e
            }
          }}
        />
      )}
    </>
  )
}
