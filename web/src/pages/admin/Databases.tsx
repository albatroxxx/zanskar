import { dbTLS, engineName } from '../../api/format'
import { DatabaseIcon } from '../../components/icons'
import type { Credential, Target } from '../../api/types'
import { Badge, Tags } from '../../components/ui'
import { TargetsPage } from './TargetsPage'

/**
 * Databases lists database targets (ADR 0017): managed endpoints such as RDS,
 * reached through a client container beside a credential-holding sidecar.
 * They share the target model with hosts but none of a host's notions
 * (probe, host key, OS), so they get their own page (manual QA finding R21).
 */
export function Databases() {
  return (
    <TargetsPage
      kind="database"
      title="Databases"
      lead="PostgreSQL, MySQL and MariaDB endpoints, including RDS. The user never sees the password."
      addLabel="Add database"
      empty="No databases yet. Add one with its engine, endpoint and a password credential."
      columns={['Engine', 'Endpoint', 'Database', 'TLS', 'Credential', 'Tags']}
      cells={(t, credentials) => (
        <>
          <td><DatabaseIcon label={engineName(t.engine)} /> {engineName(t.engine, t.engine_version)}</td>
          <td className="mono">{t.address}{t.ports.database ? `:${t.ports.database}` : ''}</td>
          <td>{t.database_name || <span className="muted">—</span>}</td>
          <td>{dbTLS(t.tls_mode).verified ? dbTLS(t.tls_mode).label : <Badge tone="warn">{dbTLS(t.tls_mode).label}</Badge>}</td>
          <td>{credentialCell(t, credentials)}</td>
          <td><Tags tags={t.tags} /></td>
        </>
      )}
    />
  )
}

function credentialCell(t: Target, credentials: Credential[]) {
  const id = t.credentials.database
  if (!id) return <Badge tone="warn">none</Badge>
  const c = credentials.find((x) => x.id === id)
  if (!c) return <span className="muted">…</span>
  return c.mode === 'user_supplied' ? <Badge>user supplied</Badge> : <span>{c.name}</span>
}
