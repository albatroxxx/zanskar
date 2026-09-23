import { useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Credential, OSFamily, Protocol, Target } from '../../api/types'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead, Tags } from '../../components/ui'
import { formatTags, hostKeyBadge, parseTags, protocols, useList, type ProbeWire } from './lib'

interface ProbeResponse { target: Target; probe: ProbeWire; host_key_status: string; host_key_fingerprint: string | null; host_key_changed_from?: string | null }

const emptyForm = { name: '', address: '', os_family: 'linux' as OSFamily, engine: '', engine_version: '', ssh: '', rdp: '', vnc: '', winrm: '', database: '', tags: '', notes: '' }

export function Targets() {
  const { items, err, setErr, reload } = useList<Target>('/targets')
  const creds = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<Target | null>(null)

  return (
    <>
      <PageHead title="Targets" lead="Machines Zanskar can reach. Probe a target to learn what it offers and pin its host key before anyone connects.">
        <button className="btn primary" onClick={() => setAdding(true)}>Add target</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No targets yet. Add one to get started.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Address</th>
                <th>OS</th>
                <th>Capabilities</th>
                <th>Host key</th>
                <th>Tags</th>
                <th>Last probed</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <strong>{t.name}</strong> {t.status === 'disabled' && <Badge>disabled</Badge>}
                  </td>
                  <td className="mono">{t.address}</td>
                  <td>{t.os_family}</td>
                  <td>
                    {t.capabilities.length === 0 ? <span className="muted">unprobed</span> : t.capabilities.map((c) => <Badge key={c} tone="accent">{c}</Badge>)}
                  </td>
                  <td>{hostKeyBadge(t.host_key_status)}</td>
                  <td><Tags tags={t.tags} /></td>
                  <td className="muted">{t.last_probed_at ? fmtTime(t.last_probed_at) : 'never'}</td>
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

function TargetForm({ initial, onClose, onSaved }: { initial?: Target; onClose: () => void; onSaved: (t: Target) => void }) {
  const [f, setF] = useState(
    initial
      ? {
          name: initial.name,
          address: initial.address,
          os_family: initial.os_family,
          engine: initial.engine ?? '',
          engine_version: initial.engine_version ?? '',
          ssh: initial.ports.ssh ? String(initial.ports.ssh) : '',
          rdp: initial.ports.rdp ? String(initial.ports.rdp) : '',
          vnc: initial.ports.vnc ? String(initial.ports.vnc) : '',
          winrm: initial.ports.winrm ? String(initial.ports.winrm) : '',
          database: initial.ports.database ? String(initial.ports.database) : '',
          tags: formatTags(initial.tags),
          notes: initial.notes,
        }
      : emptyForm,
  )
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k: keyof typeof emptyForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value })

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const { tags, error } = parseTags(f.tags)
    if (error) {
      setErr(error)
      return
    }
    const ports: Partial<Record<Protocol, number>> = {}
    for (const p of protocols) {
      const v = f[p].trim()
      if (v) {
        const n = Number(v)
        if (!Number.isInteger(n) || n < 1 || n > 65535) {
          setErr(`${p} port must be 1-65535`)
          return
        }
        ports[p] = n
      }
    }
    if (f.database.trim()) {
      const n = Number(f.database.trim())
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        setErr('database port must be 1-65535')
        return
      }
      ports.database = n
    }
    setBusy(true)
    setErr('')
    try {
      const body = {
        name: f.name.trim(),
        address: f.address.trim(),
        os_family: f.os_family,
        engine: f.engine.trim(),
        engine_version: f.engine_version.trim(),
        ports,
        capabilities: initial?.capabilities ?? [],
        tags,
        status: initial?.status ?? 'active',
        notes: f.notes,
        credentials: initial?.credentials ?? {},
      }
      const t = initial ? await api.put<Target>(`/targets/${initial.id}`, body) : await api.post<Target>('/targets', body)
      onSaved(t)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={initial ? `Edit ${initial.name}` : 'Add target'} onClose={onClose} width={620}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form onSubmit={submit}>
        <div className="form-grid">
          <Field label="Name">
            <input id="t-name" value={f.name} onChange={set('name')} required autoFocus />
          </Field>
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
          <Field label="Database engine" hint="Set only for a PaaS database target (ADR 0017)">
            <select id="t-engine" value={f.engine} onChange={set('engine')}>
              <option value="">— not a database —</option>
              <option value="postgres">PostgreSQL</option>
              <option value="mysql">MySQL</option>
              <option value="mariadb">MariaDB</option>
            </select>
          </Field>
        </div>
        <div className="form-grid">
          {protocols.map((p) => (
            <Field key={p} label={`${p.toUpperCase()} port`} hint="blank = default">
              <input id={`t-port-${p}`} inputMode="numeric" value={f[p]} onChange={set(p)} placeholder={{ ssh: '22', rdp: '3389', vnc: '5900', winrm: '5986' }[p]} />
            </Field>
          ))}
          {f.engine && (
            <>
              <Field label="Engine version" hint="e.g. 16 — selects the client image">
                <input id="t-engine-version" value={f.engine_version} onChange={set('engine_version')} placeholder="16" />
              </Field>
              <Field label="Database port" hint="blank = engine default">
                <input id="t-port-database" inputMode="numeric" value={f.database} onChange={set('database')} placeholder={({ postgres: '5432', mysql: '3306', mariadb: '3306' } as Record<string, string>)[f.engine] ?? ''} />
              </Field>
            </>
          )}
        </div>
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
    </Modal>
  )
}

function TargetDetail({ target, credentials, onClose, onChanged, onDeleted, onError }: { target: Target; credentials: Credential[]; onClose: () => void; onChanged: (t: Target) => void; onDeleted: () => void; onError: (m: string) => void }) {
  const [editing, setEditing] = useState(false)
  const [probe, setProbe] = useState<ProbeResponse | null>(null)
  const [probing, setProbing] = useState(false)
  const [confirm, setConfirm] = useState<'trust' | 'delete' | null>(null)
  const [err, setErr] = useState('')
  const t = target

  const run = async (fn: () => Promise<unknown>) => {
    setErr('')
    try {
      await fn()
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  const doProbe = () =>
    run(async () => {
      setProbing(true)
      try {
        const res = await api.post<ProbeResponse>(`/targets/${t.id}/probe`)
        setProbe(res)
        onChanged(res.target)
      } finally {
        setProbing(false)
      }
    })

  const setCredential = (p: Protocol, id: string) =>
    run(async () => {
      const updated = id ? await api.put<Target>(`/targets/${t.id}/credentials/${p}`, { credential_id: id }) : await api.del<Target>(`/targets/${t.id}/credentials/${p}`)
      onChanged(updated ?? (await api.get<Target>(`/targets/${t.id}`)))
    })

  const toggleStatus = () =>
    run(async () => {
      const body = { name: t.name, address: t.address, os_family: t.os_family, ports: t.ports, capabilities: t.capabilities, tags: t.tags, status: t.status === 'active' ? 'disabled' : 'active', notes: t.notes, credentials: t.credentials }
      onChanged(await api.put<Target>(`/targets/${t.id}`, body))
    })

  const fp = probe?.host_key_fingerprint ?? t.host_key_fingerprint
  const canTrust = (t.host_key_status === 'pending' || t.host_key_status === 'changed') && !!fp

  return (
    <Modal title={t.name} onClose={onClose} width={720}>
      {err && <Alert tone="danger">{err}</Alert>}
      {t.host_key_status === 'changed' && (
        <Alert tone="danger">
          The SSH host key changed after it was trusted. Connections are refused until an administrator confirms the new key. Verify it out of band before trusting it.
          {probe?.host_key_changed_from && (
            <div className="mono" style={{ marginTop: 6 }}>previous {probe.host_key_changed_from}</div>
          )}
        </Alert>
      )}
      <dl className="kv">
        <dt>Address</dt><dd className="mono">{t.address}</dd>
        <dt>OS</dt><dd>{t.os_family}</dd>
        <dt>Status</dt><dd>{t.status}</dd>
        <dt>Capabilities</dt><dd>{t.capabilities.length ? t.capabilities.join(', ') : <span className="muted">unprobed</span>}</dd>
        <dt>Host key</dt>
        <dd>
          {hostKeyBadge(t.host_key_status)} {fp && <span className="mono"> {fp}</span>}
        </dd>
        {t.winrm_tls_fingerprint && (
          <>
            <dt>WinRM cert</dt><dd className="mono">{t.winrm_tls_fingerprint}</dd>
          </>
        )}
        {t.tls_fingerprint && (
          <>
            <dt>RDP cert</dt><dd className="mono">{t.tls_fingerprint}</dd>
          </>
        )}
        <dt>Tags</dt><dd><Tags tags={t.tags} /></dd>
        <dt>Last probed</dt><dd>{t.last_probed_at ? fmtTime(t.last_probed_at) : 'never'}</dd>
        {t.notes && (
          <>
            <dt>Notes</dt><dd>{t.notes}</dd>
          </>
        )}
      </dl>

      <h2 style={{ marginTop: 18 }}>Credentials per protocol</h2>
      <div className="form-grid">
        {protocols.map((p) => (
          <Field key={p} label={p.toUpperCase()}>
            <select id={`cred-${p}`} value={t.credentials[p] ?? ''} onChange={(e) => void setCredential(p, e.target.value)}>
              <option value="">— none —</option>
              {credentials.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.type}, {c.mode})
                </option>
              ))}
            </select>
          </Field>
        ))}
      </div>

      {probe && (
        <>
          <h2>Probe result</h2>
          <dl className="kv">
            <dt>Resolved</dt><dd className="mono">{probe.probe.resolved_ip}</dd>
            {protocols.map((p) => {
              const r = probe.probe.ports[p]
              if (!r) return null
              return (
                <span key={p} style={{ display: 'contents' }}>
                  <dt>{p.toUpperCase()}</dt>
                  <dd>
                    {r.reachable ? <Badge tone="ok">reachable · {r.latency_ms} ms</Badge> : <Badge>unreachable</Badge>} {r.error && <span className="muted">{r.error}</span>}
                  </dd>
                </span>
              )
            })}
            {probe.probe.ssh_host_key && (
              <>
                <dt>SSH key</dt><dd className="mono">{probe.probe.ssh_host_key.type} {probe.probe.ssh_host_key.fingerprint}</dd>
                <dt>Banner</dt><dd className="mono">{probe.probe.ssh_host_key.banner}</dd>
              </>
            )}
            {probe.probe.winrm_tls && (
              <>
                <dt>WinRM cert</dt><dd className="mono">{probe.probe.winrm_tls.subject} · {probe.probe.winrm_tls.fingerprint}</dd>
              </>
            )}
            {probe.probe.tls && (
              <>
                <dt>RDP cert</dt><dd className="mono">{probe.probe.tls.subject} · {probe.probe.tls.fingerprint}</dd>
              </>
            )}
            {probe.probe.vnc_version && (
              <>
                <dt>VNC</dt><dd className="mono">{probe.probe.vnc_version}</dd>
              </>
            )}
          </dl>
        </>
      )}

      <div className="actions" style={{ marginTop: 18, justifyContent: 'space-between' }}>
        <div className="actions">
          <button className="btn" onClick={() => void doProbe()} disabled={probing}>{probing ? 'Probing…' : 'Probe'}</button>
          {canTrust && (
            <button className="btn primary" onClick={() => setConfirm('trust')}>Trust host key</button>
          )}
          <button className="btn" onClick={() => setEditing(true)}>Edit</button>
          <button className="btn" onClick={() => void toggleStatus()}>{t.status === 'active' ? 'Disable' : 'Enable'}</button>
        </div>
        <button className="btn danger" onClick={() => setConfirm('delete')}>Delete</button>
      </div>

      {editing && (
        <TargetForm
          initial={t}
          onClose={() => setEditing(false)}
          onSaved={(u) => {
            setEditing(false)
            onChanged(u)
          }}
        />
      )}
      {confirm === 'trust' && fp && (
        <Confirm
          title="Trust this host key?"
          body={
            <div>
              <p>Zanskar will only connect to <strong>{t.name}</strong> when it presents this key:</p>
              <p className="mono" style={{ wordBreak: 'break-all' }}>{fp}</p>
              {t.host_key_status === 'changed' && <Alert tone="danger">This replaces a previously trusted key. Only proceed if you confirmed the change with the machine's owner.</Alert>}
            </div>
          }
          confirmLabel="Trust"
          danger={t.host_key_status === 'changed'}
          onClose={() => setConfirm(null)}
          onConfirm={async () => {
            const res = await api.post<Target | { target: Target }>(`/targets/${t.id}/host-key/trust`, { host_key_fingerprint: fp })
            onChanged('target' in res ? res.target : res)
          }}
        />
      )}
      {confirm === 'delete' && (
        <Confirm
          title={`Delete ${t.name}?`}
          body="Policies that selected this target by id stop matching it. Past sessions keep their records."
          confirmLabel="Delete"
          danger
          onClose={() => setConfirm(null)}
          onConfirm={async () => {
            try {
              await api.del(`/targets/${t.id}`)
              onDeleted()
            } catch (e) {
              onError(errorMessage(e))
              throw e
            }
          }}
        />
      )}
    </Modal>
  )
}
