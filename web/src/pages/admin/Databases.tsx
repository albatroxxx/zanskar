import { useState } from 'react'
import { engineName } from '../../api/format'
import type { Credential, Target } from '../../api/types'
import { Alert, Badge, Empty, PageHead, Tags } from '../../components/ui'
import { useList } from './lib'
import { TargetDetail } from './TargetDetail'
import { TargetForm } from './TargetForm'

/**
 * Databases lists database targets (ADR 0017): managed endpoints such as RDS,
 * reached through a client container beside a credential-holding sidecar.
 * They share the target model with hosts but none of a host's notions
 * (probe, host key, OS), so they get their own page (manual QA finding R21).
 */
export function Databases() {
  const { items, err, setErr, reload } = useList<Target>('/targets', { kind: 'database' })
  const creds = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<Target | null>(null)
  const credentialCell = (t: Target) => {
    const id = t.credentials.database
    if (!id) return <Badge tone="warn">none</Badge>
    const c = (creds.items ?? []).find((x) => x.id === id)
    if (!c) return <span className="muted">…</span>
    return c.mode === 'user_supplied' ? <Badge>user supplied</Badge> : <span>{c.name}</span>
  }

  return (
    <>
      <PageHead title="Databases" lead="PostgreSQL, MySQL and MariaDB endpoints, including RDS. Each session runs the matching client in a container next to a sidecar that holds the credential; the user never sees the password.">
        <button className="btn primary" onClick={() => setAdding(true)}>Add database</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No databases yet. Add one with its engine, endpoint and a password credential.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Engine</th>
                <th>Endpoint</th>
                <th>Database</th>
                <th>TLS</th>
                <th>Credential</th>
                <th>Tags</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <strong>{t.name}</strong> {t.status === 'disabled' && <Badge>disabled</Badge>}
                  </td>
                  <td>{engineName(t.engine, t.engine_version)}</td>
                  <td className="mono">{t.address}{t.ports.database ? `:${t.ports.database}` : ''}</td>
                  <td>{t.database_name || <span className="muted">—</span>}</td>
                  <td>{t.tls_mode || 'prefer'}</td>
                  <td>{credentialCell(t)}</td>
                  <td><Tags tags={t.tags} /></td>
                  <td>
                    <button className="btn sm" onClick={() => setOpen(t)}>Open</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {adding && (
        <TargetForm
          kind="database"
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false)
            void reload()
          }}
        />
      )}
      {open && (
        <TargetDetail
          target={open}
          credentials={creds.items ?? []}
          onClose={() => setOpen(null)}
          onChanged={(t) => {
            setOpen(t)
            void reload()
          }}
          onDeleted={() => {
            setOpen(null)
            void reload()
          }}
          onError={setErr}
        />
      )}
    </>
  )
}
