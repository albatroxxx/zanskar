import { protocolName } from '../../api/format'
import { useState, type FormEvent } from 'react'
import { api } from '../../api/client'
import type { OSFamily, Protocol, Target } from '../../api/types'
import { useSubmit } from '../../components/submit'
import { Alert, Field, Modal, Tabs } from '../../components/ui'
import { formatTags, parseTags, protocols } from './lib'

export type TargetKind = 'host' | 'database' | 'application'

/** kindOf says what kind of target t is: an application has an upstream, a database an engine. */
export function kindOf(t: Pick<Target, 'engine' | 'app_upstream'>): TargetKind {
  return t.app_upstream ? 'application' : t.engine ? 'database' : 'host'
}

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
    app_upstream: u.app_upstream ?? '',
    app_label: u.app_label ?? '',
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
// Verified is the default (ADR 0025); the others are an explicit choice to
// connect without checking who answers.
const tlsModes = [
  { v: 'verify-full', label: 'Verified (recommended)', hint: 'TLS, with the certificate chain and host name checked against the CA bundle below' },
  { v: 'require', label: 'Encrypted, not verified', hint: 'TLS or refuse, but anyone who can intercept the connection can impersonate the database' },
  { v: 'prefer', label: 'Encrypted if offered, not verified', hint: 'TLS when the database offers it, otherwise plain; nothing is verified' },
  { v: 'disable', label: 'Not encrypted', hint: 'never TLS; only for a database on a private network' },
]

const emptyForm = {
  name: '', address: '', os_family: 'linux' as OSFamily,
  engine: 'postgres', engine_version: '', database_name: '', tls_mode: 'verify-full', tls_ca: '',
  app_upstream: '', app_label: '',
  ssh: '', rdp: '', vnc: '', winrm: '', database: '', tags: '', notes: '', retention: '',
}

/**
 * TargetForm creates or edits a target. The first choice is what kind of
 * thing it is: a host reached over SSH, RDP, VNC or WinRM, a database
 * reached through a client container and a credential-holding sidecar
 * (ADR 0017), or a web application served through the proxy at its own
 * address (ADR 0033). Each kind then shows only its own fields (manual QA
 * finding R33). Autoscaling groups have their own page.
 */
export function TargetForm({ initial, kind, onClose, onSaved }: { initial?: Target; kind?: TargetKind; onClose: () => void; onSaved: (t: Target) => void }) {
  const [k, setK] = useState<TargetKind | null>(initial ? kindOf(initial) : (kind ?? null))
  const [f, setF] = useState(
    initial
      ? {
          name: initial.name,
          address: initial.address,
          os_family: initial.os_family,
          engine: initial.engine || 'postgres',
          engine_version: initial.engine_version ?? '',
          database_name: initial.database_name ?? '',
          tls_mode: initial.tls_mode || 'verify-full',
          tls_ca: initial.tls_ca ?? '',
          app_upstream: initial.app_upstream ?? '',
          app_label: initial.app_label ?? '',
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
  const { busy, err, setErr, submit } = useSubmit()
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

  const save = (e: FormEvent) => {
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
    } else if (k === 'database') {
      const n = port('database', f.database)
      if (n === null) return
      if (n !== undefined) ports.database = n
    }
    const retention = f.retention.trim() ? Number(f.retention) : null
    if (retention !== null && (!Number.isInteger(retention) || retention < 1 || retention > 3650)) {
      setErr('retention must be 1-3650 days')
      return
    }
    void submit(async () => {
      const database = k === 'database'
      const application = k === 'application'
      const secure = application && f.app_upstream.trim().toLowerCase().startsWith('https://')
      const body = {
        name: f.name.trim(),
        // An application's address is its upstream's host; the server derives it.
        address: application ? '' : f.address.trim(),
        os_family: database || application ? 'other' : f.os_family,
        engine: database ? f.engine : '',
        engine_version: database ? f.engine_version.trim() : '',
        database_name: database ? f.database_name.trim() : '',
        tls_mode: database ? f.tls_mode : '',
        tls_ca: database || secure ? f.tls_ca.trim() : '',
        app_upstream: application ? f.app_upstream.trim() : '',
        app_label: application ? f.app_label.trim() : '',
        retention_days: application ? null : retention,
        ports,
        capabilities: initial?.capabilities ?? [],
        tags,
        status: initial?.status ?? 'active',
        notes: f.notes,
        credentials: initial?.credentials ?? {},
      }
      const t = initial ? await api.put<Target>(`/targets/${initial.id}`, body) : await api.post<Target>('/targets', body)
      onSaved(t)
    })
  }

  const title = initial ? `Edit ${initial.name}` : k === 'database' ? 'Add database' : k === 'host' ? 'Add host' : k === 'application' ? 'Add application' : 'Add target'
  const secureUpstream = f.app_upstream.trim().toLowerCase().startsWith('https://')
  return (
    <Modal title={title} onClose={onClose} width={620}>
      {err && <Alert tone="danger">{err}</Alert>}
      {!initial && !kind && (
        <>
          <Tabs label="Kind of target" value={k ?? ''} onChange={setK} tabs={[{ key: 'host', label: 'Host' }, { key: 'database', label: 'Database' }, { key: 'application', label: 'Application' }]} />
          {!k && <p className="muted">A <strong>host</strong> is a machine reached over SSH, RDP, VNC or WinRM. A <strong>database</strong> is an endpoint such as RDS, reached through a client container that never sees the password. An <strong>application</strong> is a web app served at its own address under the apps domain. Autoscaling groups are added under <em>Autoscaling</em>.</p>}
        </>
      )}
      {k && (
        <form onSubmit={save}>
          <div className="form-grid">
            <Field label="Name">
              <input id="t-name" value={f.name} onChange={set('name')} required autoFocus />
            </Field>
            {k === 'application' ? (
              <>
                <Field label="Upstream" hint="The origin the gateway forwards to, with its scheme and port, reachable from the gateway; nothing else is proxied">
                  <input id="t-upstream" value={f.app_upstream} onChange={set('app_upstream')} required placeholder="https://wiki.internal:8443" />
                </Field>
                <Field label="Label" hint="The subdomain it is served at, under the apps domain; blank derives from the name">
                  <input id="t-label" value={f.app_label} onChange={set('app_label')} placeholder="wiki" />
                </Field>
              </>
            ) : k === 'host' ? (
              <>
                <Field label="Address" hint={initial && f.address.trim() !== initial.address
                  ? 'A new address may be a different machine: saving clears the trusted host key and pinned certificates, so probe and trust it again.'
                  : 'Hostname or IP reachable from the gateway'}>
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
                <Field key={p} label={`${protocolName(p)} port`} hint="blank = default">
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
                <Field label="CA bundle (PEM)" hint="The certificate authority that signs the database's certificate. For Amazon RDS, paste your region's bundle from truststore.pki.rds.amazonaws.com/<region>/<region>-bundle.pem (the global bundle is too large). Kept if you switch modes later.">
                  <textarea id="t-tls-ca" value={f.tls_ca} onChange={set('tls_ca')} placeholder="-----BEGIN CERTIFICATE-----" required />
                </Field>
              )}
            </>
          )}
          {k === 'application' && secureUpstream && (
            <Field label="CA bundle (PEM, optional)" hint="The authority that signs the upstream's certificate; blank verifies against the system roots. The connection is always verified.">
              <textarea id="t-tls-ca" value={f.tls_ca} onChange={set('tls_ca')} placeholder="-----BEGIN CERTIFICATE-----" />
            </Field>
          )}
          {k !== 'application' && (
            <Field label="Keep recordings (days, blank = policy's or global)" hint="Overrides the policy's retention for this target's sessions">
              <input id="t-retention" inputMode="numeric" value={f.retention} onChange={set('retention')} />
            </Field>
          )}
          <Field label="Tags" hint="One key=value per line; policies select targets by tag">
            <textarea id="t-tags" value={f.tags} onChange={set('tags')} placeholder={'env=prod\nteam=ops'} />
          </Field>
          <Field label="Notes">
            <textarea id="t-notes" value={f.notes} onChange={set('notes')} style={{ minHeight: 50 }} />
          </Field>
          <div className="actions">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn primary" disabled={busy}>{initial ? 'Save' : 'Create'}</button>
          </div>
        </form>
      )}
    </Modal>
  )
}
