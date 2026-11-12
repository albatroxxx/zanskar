import { count, protocolName } from '../../api/format'
import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../../api/client'
import { errorMessage } from '../../api/client'
import type { AppEndpoint, OSFamily, Protocol, RetentionPolicy, Target } from '../../api/types'
import { useSubmit } from '../../components/submit'
import { Alert, Field, Modal, Tabs } from '../../components/ui'
import { EndpointEditor } from './EndpointEditor'
import { endpointsBody, endpointWords, privateBody, privateWords } from './endpoints'
import { protocols, type PortProtocol } from './lib'
import { TagEditor } from '../../components/TagEditor'
import { rowsToTags, tagRows, type TagRow } from '../../components/tags'

export type TargetKind = 'host' | 'database' | 'application' | 'kubernetes'

/** kindOf says what kind of target t is: an application has an upstream, a database an engine, a cluster an API server. */
export function kindOf(t: Pick<Target, 'engine' | 'app_upstream' | 'kube_api_server'>): TargetKind {
  return t.app_upstream ? 'application' : t.engine ? 'database' : t.kube_api_server ? 'kubernetes' : 'host'
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
    // Every write replaces the target, so an edit made elsewhere (a status
    // switch) carries the endpoints or would drop them.
    app_endpoints: u.app_endpoints ?? [],
    app_dependencies: u.app_dependencies ?? '',
    app_private: u.app_private ?? null,
    kube_api_server: u.kube_api_server ?? '',
    kube_ca: u.kube_ca ?? '',
    kube_impersonate: u.kube_impersonate ?? null,
    retention_days: u.retention_days ?? null,
    ports: u.ports,
    capabilities: u.capabilities,
    tags: u.tags,
    status: u.status,
    notes: u.notes,
    credentials: u.credentials,
  }
}

export const enginePorts: Record<string, string> = { postgres: '5432', mysql: '3306', mariadb: '3306' }
/** The ports a host field starts with; a value left at its default is stored as unset. */
const defaultPorts: Record<PortProtocol, string> = { ssh: '22', rdp: '3389', vnc: '5900', winrm: '5986' }
/**
 * hostPorts is which port fields an operating system shows (2026-10-30: a
 * Linux host offered RDP, VNC and WinRM too): its usual protocols, and the
 * rarer ones it can serve behind More ports. Other shows all four.
 */
export const hostPorts: Record<OSFamily, { main: PortProtocol[]; more: PortProtocol[] }> = {
  linux: { main: ['ssh'], more: ['vnc'] },
  windows: { main: ['rdp', 'winrm'], more: ['ssh'] },
  other: { main: ['ssh', 'rdp', 'vnc', 'winrm'], more: [] },
}
// Verified is the default (ADR 0025); the others are an explicit choice to
// connect without checking who answers.
const tlsModes = [
  { v: 'verify-full', label: 'Verified (recommended)', hint: 'Chain and host name checked' },
  { v: 'require', label: 'Encrypted, not verified', hint: 'Open to impersonation' },
  { v: 'prefer', label: 'Encrypted if offered, not verified', hint: 'May fall back to plain text' },
  { v: 'disable', label: 'Not encrypted', hint: 'Private networks only' },
]

const emptyForm = {
  name: '', address: '', os_family: 'linux' as OSFamily,
  engine: 'postgres', engine_version: '', database_name: '', tls_mode: 'verify-full', tls_ca: '',
  app_upstream: '', endpoints: [] as AppEndpoint[], dependencies: 'public' as 'public' | 'origins', private_networks: '', private_hosts: '',
  kube_api_server: '', kube_ca: '', kube_impersonate: true,
  ...defaultPorts, database: enginePorts.postgres, tags: [] as TagRow[], notes: '', retention: '',
}

/**
 * TargetForm creates or edits a target. The first choice is what kind of
 * thing it is: a host reached over SSH, RDP, VNC or WinRM, a database
 * reached through a client container and a credential-holding sidecar
 * (ADR 0017), or a web application opened in an isolated browser beside the
 * gateway (ADR 0034). Each kind then shows only its own fields (manual QA
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
          kube_api_server: initial.kube_api_server ?? '',
          kube_ca: initial.kube_ca ?? '',
          kube_impersonate: initial.kube_impersonate ?? true,
          endpoints: (initial.app_endpoints ?? []).map((e) => ({ ...e })),
          dependencies: initial.app_dependencies ?? 'public',
          private_networks: (initial.app_private?.networks ?? []).join('\n'),
          private_hosts: (initial.app_private?.hosts ?? []).join('\n'),
          ssh: initial.ports.ssh ? String(initial.ports.ssh) : defaultPorts.ssh,
          rdp: initial.ports.rdp ? String(initial.ports.rdp) : defaultPorts.rdp,
          vnc: initial.ports.vnc ? String(initial.ports.vnc) : defaultPorts.vnc,
          winrm: initial.ports.winrm ? String(initial.ports.winrm) : defaultPorts.winrm,
          database: initial.ports.database ? String(initial.ports.database) : (enginePorts[initial.engine || 'postgres'] ?? ''),
          tags: tagRows(initial.tags),
          notes: initial.notes,
          retention: initial.retention_days ? String(initial.retention_days) : '',
        }
      : emptyForm,
  )
  const { busy, err, setErr, submit } = useSubmit()
  const set = (key: keyof typeof emptyForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [key]: e.target.value })
  const [moreOpen, setMoreOpen] = useState(false)
  // A port changed from its default always shows, whatever the operating
  // system, so a value is never hidden and kept in silence.
  const set_ = hostPorts[f.os_family] ?? hostPorts.other
  const changed = protocols.filter((p) => f[p].trim() !== defaultPorts[p])
  const shownPorts = protocols.filter((p) => set_.main.includes(p) || (moreOpen && set_.more.includes(p)) || changed.includes(p))
  const hiddenMore = set_.more.filter((p) => !shownPorts.includes(p))
  const [globalRetention, setGlobalRetention] = useState<string>('')
  useEffect(() => {
    api
      .get<RetentionPolicy>('/admin/retention')
      .then((r) => setGlobalRetention(r.max_age_days > 0 ? count(r.max_age_days, 'day') : 'no age limit'))
      .catch(() => setGlobalRetention(''))
  }, [])

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
    const { tags, error } = rowsToTags(f.tags)
    if (error) {
      setErr(error)
      return
    }
    // A port at its default is stored unset, as it always was: the field
    // shows the number instead of saying "blank = default".
    const ports: Partial<Record<Protocol, number>> = {}
    if (k === 'host') {
      for (const p of protocols) {
        const n = port(p, f[p])
        if (n === null) return
        if (n !== undefined && String(n) !== defaultPorts[p]) ports[p] = n
      }
    } else if (k === 'database') {
      const n = port('database', f.database)
      if (n === null) return
      if (n !== undefined && String(n) !== enginePorts[f.engine]) ports.database = n
    }
    const retention = f.retention.trim() ? Number(f.retention) : null
    if (retention !== null && (!Number.isInteger(retention) || retention < 1 || retention > 3650)) {
      setErr('retention must be 1-3650 days')
      return
    }
    const endpoints = endpointsBody(k === 'application' ? f.endpoints : [])
    if (endpoints.error) {
      setErr(endpoints.error)
      return
    }
    void submit(async () => {
      const database = k === 'database'
      const application = k === 'application'
      const cluster = k === 'kubernetes'
      const secure = application && secureOrigins
      const body = {
        name: f.name.trim(),
        // An application's address is its upstream's host, a cluster's its API server's; the server derives it.
        address: application || cluster ? '' : f.address.trim(),
        os_family: database || application || cluster ? 'other' : f.os_family,
        engine: database ? f.engine : '',
        engine_version: database ? f.engine_version.trim() : '',
        database_name: database ? f.database_name.trim() : '',
        tls_mode: database ? f.tls_mode : '',
        tls_ca: database || secure ? f.tls_ca.trim() : '',
        app_upstream: application ? f.app_upstream.trim() : '',
        app_endpoints: endpoints.body,
        app_dependencies: application ? f.dependencies : '',
        app_private: application ? privateBody(f.private_networks, f.private_hosts) : null,
        kube_api_server: cluster ? f.kube_api_server.trim() : '',
        kube_ca: cluster ? f.kube_ca.trim() : '',
        kube_impersonate: cluster ? f.kube_impersonate : null,
        retention_days: application ? null : retention,
        ports,
        capabilities: initial?.capabilities ?? [],
        tags,
        status: initial?.status ?? 'active',
        notes: f.notes,
        credentials: initial?.credentials ?? {},
      }
      let t: Target
      try {
        t = initial ? await api.put<Target>(`/targets/${initial.id}`, body) : await api.post<Target>('/targets', body)
      } catch (e) {
        // The server names a row by its place in what was sent; say it as
        // the row the person filled in.
        throw new Error(privateWords(endpointWords(errorMessage(e), endpoints.sent)))
      }
      onSaved(t)
    })
  }

  const title = initial ? `Edit ${initial.name}` : k === 'database' ? 'Add database' : k === 'host' ? 'Add host' : k === 'application' ? 'Add application' : k === 'kubernetes' ? 'Add cluster' : 'Add target'
  // The CA bundle applies when any origin is https, the upstream or another.
  const secureOrigins = [f.app_upstream, ...f.endpoints.map((e) => e.url)].some((u) => u.trim().toLowerCase().startsWith('https://'))
  return (
    <Modal title={title} onClose={onClose} width={620} anchored>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {!initial && !kind && (
        <>
          <Tabs label="Kind of target" value={k ?? ''} onChange={setK} tabs={[{ key: 'host', label: 'Host' }, { key: 'database', label: 'Database' }, { key: 'application', label: 'Application' }, { key: 'kubernetes', label: 'Kubernetes' }]} />
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
                <Field label="Upstream">
                  <input id="t-upstream" value={f.app_upstream} onChange={set('app_upstream')} required placeholder="https://wiki.internal:8443" />
                </Field>
              </>
            ) : k === 'kubernetes' ? (
              <>
                <Field label="API server">
                  <input id="t-kube-api-server" value={f.kube_api_server} onChange={set('kube_api_server')} required placeholder="https://k8s.internal:6443" />
                </Field>
                <Field label="Sessions act as">
                  <select id="t-kube-impersonate" value={f.kube_impersonate ? 'person' : 'credential'} onChange={(e) => setF({ ...f, kube_impersonate: e.target.value === 'person' })}>
                    <option value="person">The person</option>
                    <option value="credential">The credential (shared identity)</option>
                  </select>
                </Field>
              </>
            ) : k === 'host' ? (
              <>
                <Field label="Hostname or IP address" hint={initial && f.address.trim() !== initial.address
                  ? 'New address: saving clears the trusted host key and pinned certificates.'
                  : undefined}>
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
                <Field label="Engine">
                  <select id="t-engine" value={f.engine} onChange={(e) => setF({ ...f, engine: e.target.value, database: f.database === enginePorts[f.engine] ? (enginePorts[e.target.value] ?? '') : f.database })}>
                    <option value="postgres">PostgreSQL</option>
                    <option value="mysql">MySQL</option>
                    <option value="mariadb">MariaDB</option>
                  </select>
                </Field>
                <Field label="Endpoint" hint="e.g. the RDS endpoint">
                  <input id="t-address" value={f.address} onChange={set('address')} required />
                </Field>
                <Field label="Port">
                  <input id="t-port-database" inputMode="numeric" value={f.database} onChange={set('database')} />
                </Field>
              </>
            )}
          </div>
          {k === 'host' && (
            <>
              <div className="form-grid">
                {shownPorts.map((p) => (
                  <Field key={p} label={`${protocolName(p)} port`}>
                    <input id={`t-port-${p}`} inputMode="numeric" value={f[p]} onChange={set(p)} />
                  </Field>
                ))}
              </div>
              {hiddenMore.length > 0 && (
                <button type="button" className="link-btn" aria-expanded={moreOpen} onClick={() => setMoreOpen(true)}>
                  More ports ({hiddenMore.map(protocolName).join(', ')})
                </button>
              )}
            </>
          )}
          {k === 'database' && (
            <>
              <div className="form-grid">
                <Field label="Engine version" hint="e.g. 16 or 8.4">
                  <input id="t-engine-version" value={f.engine_version} onChange={set('engine_version')} placeholder={f.engine === 'postgres' ? '16' : '8'} />
                </Field>
                <Field label="Database">
                  <input id="t-database-name" value={f.database_name} onChange={set('database_name')} placeholder={f.engine === 'postgres' ? 'The login role\'s name' : 'None'} />
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
                <Field label="CA bundle (PEM)" hint="For RDS: truststore.pki.rds.amazonaws.com/<region>/<region>-bundle.pem">
                  <textarea id="t-tls-ca" value={f.tls_ca} onChange={set('tls_ca')} placeholder="-----BEGIN CERTIFICATE-----" required />
                </Field>
              )}
            </>
          )}
          {k === 'kubernetes' && (
            <Field label="CA bundle (PEM)">
              <textarea id="t-kube-ca" value={f.kube_ca} onChange={set('kube_ca')} placeholder="System roots" />
            </Field>
          )}
          {k === 'application' && (
            <Field label="Other endpoints" info="Bookmarks in its browser; pages open nowhere else.">
              <EndpointEditor rows={f.endpoints} onChange={(endpoints) => setF({ ...f, endpoints })} />
            </Field>
          )}
          {k === 'application' && (
            <Field label="Dependencies" info="Any public address goes through a relay that reads the requests.">
              <select id="t-dependencies" value={f.dependencies} onChange={(e) => setF({ ...f, dependencies: e.target.value as 'public' | 'origins' })}>
                <option value="public">Any public address</option>
                <option value="origins">Its origins only</option>
              </select>
            </Field>
          )}
          {k === 'application' && f.dependencies === 'public' && (
            <div className="row2">
              <Field label="Private networks" info="CIDR, one per line; other private addresses are refused.">
                <textarea id="t-private-networks" value={f.private_networks} onChange={set('private_networks')} placeholder={'10.20.0.0/16'} rows={3} />
              </Field>
              <Field label="Private hosts" info="host:port, one per line.">
                <textarea id="t-private-hosts" value={f.private_hosts} onChange={set('private_hosts')} placeholder={'cdn.corp:443'} rows={3} />
              </Field>
            </div>
          )}
          {k === 'application' && secureOrigins && (
            <Field label="CA bundle (PEM, optional)">
              <textarea id="t-tls-ca" value={f.tls_ca} onChange={set('tls_ca')} placeholder="System roots" />
            </Field>
          )}
          {k !== 'application' && (
            <Field label="Recording retention (days)" info="Empty: the grant's, then global.">
              <input id="t-retention" inputMode="numeric" value={f.retention} onChange={set('retention')} placeholder={globalRetention ? `Global: ${globalRetention}` : 'Global'} />
            </Field>
          )}
          <Field label="Tags">
            <TagEditor idPrefix="t-tag" rows={f.tags} onChange={(tags) => setF({ ...f, tags })} />
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
