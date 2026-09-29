import { useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import type { OSFamily, Protocol, Target } from '../../api/types'
import { Alert, Field, Modal } from '../../components/ui'
import { formatTags, parseTags, protocols } from './lib'

export type TargetKind = 'host' | 'database'

/** Body of POST/PUT /targets: every editable field travels on each write. */
export function targetBody(t: Target, patch: Partial<Target> = {}) {
  const u = { ...t, ...patch }
  return {
    name: u.name,
    address: u.address,
    os_family: u.os_family,
    engine: u.engine ?? '',
    engine_version: u.engine_version ?? '',
    database_name: u.database_name ?? '',
    tls_mode: u.tls_mode ?? '',
    tls_ca: u.tls_ca ?? '',
    retention_days: u.retention_days ?? null,
    ports: u.ports,
    capabilities: u.capabilities,
    tags: u.tags,
    status: u.status,
    notes: u.notes,
    credentials: u.credentials,
  }
}

const enginePorts: Record<string, string> = { postgres: '5432', mysql: '3306', mariadb: '3306' }
const tlsModes = [
  { v: 'prefer', label: 'Prefer', hint: 'TLS when the database offers it, unverified (default)' },
  { v: 'require', label: 'Require', hint: 'TLS or refuse; the certificate is not verified' },
  { v: 'verify-full', label: 'Verify full', hint: 'TLS, certificate chain and host name verified against the CA bundle below' },
  { v: 'disable', label: 'Disable', hint: 'never TLS; only for a database on a private network' },
]

const emptyForm = {
  name: '', address: '', os_family: 'linux' as OSFamily,
  engine: 'postgres', engine_version: '', database_name: '', tls_mode: 'prefer', tls_ca: '',
  ssh: '', rdp: '', vnc: '', winrm: '', database: '', tags: '', notes: '', retention: '',
}

/**
 * TargetForm creates or edits a target. The first choice is what kind of
 * thing it is: a host reached over SSH, RDP, VNC or WinRM, or a database
 * reached through a client container and a credential-holding sidecar
 * (ADR 0017). Each kind then shows only its own fields (manual QA finding
 * R33). Autoscaling groups have their own page.
 */
export function TargetForm({ initial, kind, onClose, onSaved }: { initial?: Target; kind?: TargetKind; onClose: () => void; onSaved: (t: Target) => void }) {
  const [k, setK] = useState<TargetKind | null>(initial ? (initial.engine ? 'database' : 'host') : (kind ?? null))
  const [f, setF] = useState(
    initial
      ? {
          name: initial.name,
          address: initial.address,
          os_family: initial.os_family,
          engine: initial.engine || 'postgres',
          engine_version: initial.engine_version ?? '',
          database_name: initial.database_name ?? '',
          tls_mode: initial.tls_mode || 'prefer',
          tls_ca: initial.tls_ca ?? '',
          ssh: initial.ports.ssh ? String(initial.ports.ssh) : '',
          rdp: initial.ports.rdp ? String(initial.ports.rdp) : '',
          vnc: initial.ports.vnc ? String(initial.ports.vnc) : '',
          winrm: initial.ports.winrm ? String(initial.ports.winrm) : '',
          database: initial.ports.database ? String(initial.ports.database) : '',
          tags: formatTags(initial.tags),
          notes: initial.notes,
          retention: initial.retention_days ? String(initial.retention_days) : '',
        }
      : emptyForm,
  )
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (key: keyof typeof emptyForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [key]: e.target.value })

  const port = (label: string, raw: string): number | null | undefined => {
    const v = raw.trim()
    if (!v) return undefined
    const n = Number(v)
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      setErr(`${label} port must be 1-65535`)
      return null
    }
    return n
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!k) return
    const { tags, error } = parseTags(f.tags)
    if (error) {
      setErr(error)
      return
    }
    const ports: Partial<Record<Protocol, number>> = {}
    if (k === 'host') {
      for (const p of protocols) {
        const n = port(p, f[p])
        if (n === null) return
        if (n !== undefined) ports[p] = n
      }
    } else {
      const n = port('database', f.database)
      if (n === null) return
      if (n !== undefined) ports.database = n
    }
    const retention = f.retention.trim() ? Number(f.retention) : null
    if (retention !== null && (!Number.isInteger(retention) || retention < 1 || retention > 3650)) {
      setErr('retention must be 1-3650 days')
      return
    }
    setBusy(true)
    setErr('')
    try {
      const database = k === 'database'
      const body = {
        name: f.name.trim(),
        address: f.address.trim(),
        os_family: database ? 'other' : f.os_family,
        engine: database ? f.engine : '',
        engine_version: database ? f.engine_version.trim() : '',
        database_name: database ? f.database_name.trim() : '',
        tls_mode: database ? f.tls_mode : '',
        tls_ca: database ? f.tls_ca.trim() : '',
        retention_days: retention,
        ports,
        capabilities: initial?.capabilities ?? [],
        tags,
        status: initial?.status ?? 'active',
        notes: f.notes,
        credentials: initial?.credentials ?? {},
      }
      const t = initial ? await api.put<Target>(`/targets/${initial.id}`, body) : await api.post<Target>('/targets', body)
      onSaved(t)
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  const title = initial ? `Edit ${initial.name}` : k === 'database' ? 'Add database' : k === 'host' ? 'Add host' : 'Add target'
  return (
    <Modal title={title} onClose={onClose} width={620}>
      {err && <Alert tone="danger">{err}</Alert>}
      {!initial && !kind && (
        <>
          <div className="tabs" style={{ marginBottom: 12 }}>
            <button type="button" className={k === 'host' ? 'active' : ''} onClick={() => setK('host')}>Host</button>
            <button type="button" className={k === 'database' ? 'active' : ''} onClick={() => setK('database')}>Database</button>
          </div>
          {!k && <p className="muted">A <strong>host</strong> is a machine reached over SSH, RDP, VNC or WinRM. A <strong>database</strong> is an endpoint such as RDS, reached through a client container that never sees the password. Autoscaling groups are added under <em>Autoscaling</em>.</p>}
        </>
      )}
      {k && (
        <form onSubmit={submit}>
          <div className="form-grid">
            <Field label="Name">
              <input id="t-name" value={f.name} onChange={set('name')} required autoFocus />
            </Field>
            {k === 'host' ? (
              <>
                <Field label="Address" hint="Hostname or IP reachable from the gateway">
                  <input id="t-address" value={f.address} onChange={set('address')} required />
                </Field>
                <Field label="Operating system">
                  <select id="t-os" value={f.os_family} onChange={set('os_family')}>
                    <option value="linux">Linux</option>
                    <option value="windows">Windows</option>
                    <option value="other">Other</option>
                  </select>
                </Field>
              </>
            ) : (
              <>
                <Field label="Engine" hint="Selects the client and the sidecar">
                  <select id="t-engine" value={f.engine} onChange={set('engine')}>
                    <option value="postgres">PostgreSQL</option>
                    <option value="mysql">MySQL</option>
                    <option value="mariadb">MariaDB</option>
                  </select>
                </Field>
                <Field label="Endpoint" hint="Hostname reachable from the gateway, e.g. the RDS endpoint">
                  <input id="t-address" value={f.address} onChange={set('address')} required />
                </Field>
                <Field label="Port" hint="blank = engine default">
                  <input id="t-port-database" inputMode="numeric" value={f.database} onChange={set('database')} placeholder={enginePorts[f.engine] ?? ''} />
                </Field>
              </>
            )}
          </div>
          {k === 'host' && (
            <div className="form-grid">
              {protocols.map((p) => (
                <Field key={p} label={`${p.toUpperCase()} port`} hint="blank = default">
                  <input id={`t-port-${p}`} inputMode="numeric" value={f[p]} onChange={set(p)} placeholder={{ ssh: '22', rdp: '3389', vnc: '5900', winrm: '5986' }[p]} />
                </Field>
              ))}
            </div>
          )}
          {k === 'database' && (
            <>
              <div className="form-grid">
                <Field label="Engine version" hint="e.g. 16 or 8.4; selects the matching client image">
                  <input id="t-engine-version" value={f.engine_version} onChange={set('engine_version')} placeholder={f.engine === 'postgres' ? '16' : '8'} />
                </Field>
                <Field label="Database" hint={f.engine === 'postgres' ? 'blank = a database named after the login role' : 'blank = none selected; users pick one with USE'}>
                  <input id="t-database-name" value={f.database_name} onChange={set('database_name')} />
                </Field>
                <Field label="TLS to the database" hint={tlsModes.find((m) => m.v === f.tls_mode)?.hint}>
                  <select id="t-tls-mode" value={f.tls_mode} onChange={set('tls_mode')}>
                    {tlsModes.map((m) => (
                      <option key={m.v} value={m.v}>{m.label}</option>
                    ))}
                  </select>
                </Field>
              </div>
              {f.tls_mode === 'verify-full' && (
                <Field label="CA bundle (PEM)" hint="The certificate authority that signs the database's certificate, e.g. the provider's bundle (for RDS, the region's rds-ca bundle). Kept if you switch modes later.">
                  <textarea id="t-tls-ca" value={f.tls_ca} onChange={set('tls_ca')} placeholder="-----BEGIN CERTIFICATE-----" required />
                </Field>
              )}
            </>
          )}
          <Field label="Keep recordings (days, blank = policy's or global)" hint="Overrides the policy's retention for this target's sessions">
            <input id="t-retention" inputMode="numeric" value={f.retention} onChange={set('retention')} />
          </Field>
          <Field label="Tags" hint="One key=value per line; policies select targets by tag">
            <textarea id="t-tags" value={f.tags} onChange={set('tags')} placeholder={'env=prod\nteam=ops'} />
          </Field>
          <Field label="Notes">
            <textarea id="t-notes" value={f.notes} onChange={set('notes')} style={{ minHeight: 50 }} />
          </Field>
          <div className="actions">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button className="btn primary" disabled={busy}>{initial ? 'Save' : 'Create'}</button>
          </div>
        </form>
      )}
    </Modal>
  )
}
