import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { appTLS, dbTLS, engineName, fmtTime, protocolName } from '../../api/format'
import type { CertificateProbe, Credential, DependencyRefusal, ProbeResponse, Protocol, Target } from '../../api/types'
import { OSIcon, StateIcon } from '../../components/icons'
import { Alert, Badge, Confirm, Modal, Tags } from '../../components/ui'
import { DeleteAsset } from './DeleteAsset'
import { hostKeyBadge, protocols, usesHostKey } from './lib'
import { CredentialBindings, type BindingChange } from './Bindings'
import { enginePorts, hostPorts, kindOf, TargetForm, targetBody } from './TargetForm'

/**
 * TargetDetail is the drawer for one host, database or application. A host
 * shows its probe state, host key and per-protocol credentials; a database
 * shows its engine, endpoint and TLS settings, a single credential slot and a
 * test of its port, since host keys do not apply to it; an application shows its
 * upstream and how it is verified, and holds no credential at all (ADR 0034).
 */
export function TargetDetail({ target, credentials, onClose, onChanged, onDeleted }: { target: Target; credentials: Credential[]; onClose: () => void; onChanged: (t: Target) => void; onDeleted: () => void; onError: (m: string) => void }) {
  const [editing, setEditing] = useState(false)
  const [probe, setProbe] = useState<ProbeResponse | null>(null)
  const [probing, setProbing] = useState(false)
  const [certProbe, setCertProbe] = useState<CertificateProbe | null>(null)
  const [certProbing, setCertProbing] = useState(false)
  const [toggling, setToggling] = useState(false)
  const [confirm, setConfirm] = useState<'trust' | 'delete' | null>(null)
  // The RDP or WinRM certificate the administrator is about to accept.
  const [trustCert, setTrustCert] = useState<{ protocol: 'rdp' | 'winrm'; pinned: string; seen: string } | null>(null)
  const [err, setErr] = useState('')
  // What the application's sessions were refused as dependencies (ADR
  // 0037, amended 2026-11-03, later), learned from the relay; read when
  // the dependencies may come from anywhere, which is when it fills.
  const [blocked, setBlocked] = useState<DependencyRefusal[] | null>(null)
  const t = target
  const kind = kindOf(t)
  const database = kind === 'database'
  const application = kind === 'application'
  const host = kind === 'host'
  const learns = application && t.app_dependencies !== 'origins'
  useEffect(() => {
    if (!learns) return
    api
      .get<{ items: DependencyRefusal[] }>(`/targets/${t.id}/dependencies`)
      .then((r) => setBlocked(r.items))
      .catch(() => setBlocked([]))
  }, [t.id, learns])

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

  // Bindings are applied one protocol at a time so each change leaves its own
  // audit event (target.credential.set / unset); the drawer shows the target
  // as the API last returned it.
  const saveBindings = async (changes: BindingChange[]) => {
    setErr('')
    let latest = t
    for (const { protocol, credential_id } of changes) {
      const updated = credential_id ? await api.put<Target>(`/targets/${t.id}/credentials/${protocol}`, { credential_id }) : await api.del<Target>(`/targets/${t.id}/credentials/${protocol}`)
      latest = updated ?? (await api.get<Target>(`/targets/${t.id}`))
    }
    onChanged(latest)
  }

  // Disable and Enable are one button, so a second click undoes the first.
  // It is off while the change is in flight, and the second click of a
  // double-click is ignored: on a quick network the first change has
  // already answered when it lands, and the button reads Enable by then.
  const toggleStatus = (click: { detail: number }) => {
    if (click.detail > 1) return
    void run(async () => {
      setToggling(true)
      try {
        onChanged(await api.put<Target>(`/targets/${t.id}`, targetBody(t, { status: t.status === 'active' ? 'disabled' : 'active' })))
      } finally {
        setToggling(false)
      }
    })
  }

  // A certificate login test applies when the SSH slot holds an authority
  // and the host key is trusted; it is a real login, so it is a button, not
  // part of the ordinary probe.
  const sshCA = host && t.credentials?.ssh ? credentials.find((c) => c.id === t.credentials.ssh && c.type === 'ssh_ca') : undefined
  const testCertificate = () =>
    run(async () => {
      setCertProbing(true)
      try {
        setCertProbe(await api.post<CertificateProbe>(`/targets/${t.id}/probe-certificate`, { key: 'current' }))
      } finally {
        setCertProbing(false)
      }
    })

  const fp = probe?.host_key_fingerprint ?? t.host_key_fingerprint
  const canTrust = host && (t.host_key_status === 'pending' || t.host_key_status === 'changed') && !!fp
  const port = t.ports.database
  // A host offers a credential slot for its operating system's usual
  // protocols (as its form shows their ports), for any its probe found or
  // an administrator gave a port, and for any already holding a credential
  // so it can be taken off. Live, 2026-11-11: an SSH-only Linux host offered
  // RDP, VNC and WinRM slots; and by the probe alone, a port closed at the
  // moment of probing would hide its slot (review, same day).
  const usual = (hostPorts[t.os_family] ?? hostPorts.other).main
  const slotProtocols: Protocol[] = database
    ? ['database']
    : protocols.filter((p) => usual.includes(p) || t.capabilities.includes(p) || !!t.ports[p] || !!t.credentials?.[p])
  // What a probe reached: a host's protocols, or a database's own port.
  const probed: Protocol[] = database ? ['database'] : protocols

  return (
    <Modal title={t.name} onClose={onClose} width={720}>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {t.host_key_status === 'changed' && (
        <Alert tone="danger">
          The SSH host key changed after it was trusted. Connections are refused until an administrator confirms the new key. Verify it out of band before trusting it.
          {probe?.host_key_changed_from && (
            <div className="mono" style={{ marginTop: 6 }}>previous {probe.host_key_changed_from}</div>
          )}
        </Alert>
      )}
      {([
        ['rdp', 'RDP', t.tls_fingerprint, t.tls_fingerprint_pending, t.tls_status],
        ['winrm', 'WinRM', t.winrm_tls_fingerprint, t.winrm_tls_fingerprint_pending, t.winrm_tls_status],
      ] as const).map(([protocol, label, pinned, seen, status]) =>
        status === 'changed' && pinned && seen ? (
          <Alert key={protocol} tone="danger">
            The {label} certificate changed after it was pinned. {label} connections are refused until an administrator accepts the new one; check it with the machine's owner first.
            <div className="mono" style={{ marginTop: 6, wordBreak: 'break-all' }}>pinned {pinned}<br />now {seen}</div>
            <div className="actions" style={{ marginTop: 8 }}>
              <button className="btn" onClick={() => setTrustCert({ protocol, pinned, seen })}>Accept the new {label} certificate…</button>
            </div>
          </Alert>
        ) : null,
      )}
      <dl className="kv">
        {database ? (
          <>
            <dt>Engine</dt><dd>{engineName(t.engine, t.engine_version)}</dd>
            <dt>Endpoint</dt><dd className="mono">{t.address}{port ? `:${port}` : ''}</dd>
            <dt>Database</dt><dd>{t.database_name || <span className="muted">{t.engine === 'postgres' ? 'named after the login role' : 'none selected; users pick one with USE'}</span>}</dd>
            <dt>TLS</dt>
            <dd>
              {dbTLS(t.tls_mode).verified ? <Badge tone="ok">{dbTLS(t.tls_mode).label} against the CA bundle</Badge> : <Badge tone="warn">{dbTLS(t.tls_mode).label}</Badge>}
            </dd>
          </>
        ) : application ? (
          <>
            <dt>Upstream</dt><dd className="mono">{t.app_upstream}</dd>
            <dt>Dependencies</dt>
            <dd>
              {t.app_dependencies === 'origins' ? 'Its origins only' : 'Any public address'}
              {t.app_dependencies !== 'origins' && (t.app_private?.networks?.length || t.app_private?.hosts?.length) ? (
                <span className="muted"> · and {[...(t.app_private?.networks ?? []), ...(t.app_private?.hosts ?? [])].join(', ')}</span>
              ) : null}
            </dd>
            {(t.app_endpoints?.length ?? 0) > 0 && (
              <>
                <dt>Other endpoints</dt>
                <dd>
                  <ul className="plain-list">
                    {t.app_endpoints?.map((e) => (
                      <li key={e.url}>{e.name} <span className="mono muted">{e.url}</span></li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            <dt>Upstream TLS</dt><dd>{appTLS(t).verified ? <Badge tone="ok">{appTLS(t).label}</Badge> : <Badge tone="warn">{appTLS(t).label}</Badge>}</dd>
            {learns && (
              <>
                <dt>Blocked</dt>
                <dd>
                  <BlockedDependencies
                    target={t}
                    items={blocked}
                    onAllow={(hostport) =>
                      run(async () => {
                        const hosts = [...(t.app_private?.hosts ?? []), hostport]
                        const u = await api.put<Target>(`/targets/${t.id}`, targetBody(t, { app_private: { ...(t.app_private ?? {}), hosts } }))
                        setBlocked((b) => (b ?? []).filter((x) => `${x.host}:${x.port}` !== hostport))
                        onChanged(u)
                      })
                    }
                    onClear={() =>
                      run(async () => {
                        await api.del(`/targets/${t.id}/dependencies`)
                        setBlocked([])
                      })
                    }
                  />
                </dd>
              </>
            )}
          </>
        ) : (
          <>
            <dt>Address</dt><dd className="mono">{t.address}</dd>
            <dt>OS</dt><dd><OSIcon os={t.os_family} /></dd>
          </>
        )}
        <dt>Status</dt><dd>{t.status}</dd>
        {host && (
          <>
            <dt>Capabilities</dt><dd>{t.capabilities.length ? t.capabilities.map(protocolName).join(', ') : <span className="muted">{t.last_probed_at ? 'none found' : 'unprobed'}</span>}</dd>
          </>
        )}
        {host && usesHostKey(t) && (
          <>
            <dt>Host key</dt>
            <dd>
              {hostKeyBadge(t.host_key_status)} {fp && <span className="mono"> {fp}</span>}
            </dd>
          </>
        )}
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
        {host && (
          <>
            <dt>Last probed</dt><dd>{t.last_probed_at ? fmtTime(t.last_probed_at) : 'never'}</dd>
          </>
        )}
        {t.notes && (
          <>
            <dt>Notes</dt><dd>{t.notes}</dd>
          </>
        )}
      </dl>

      {/* An application holds no credential: people sign in to it as
          themselves, inside the isolated browser (ADR 0034). A
          database target has one slot, the brokered "database" protocol; the
          host slots (ssh, rdp, vnc, winrm) do not apply to it. */}
      {!application && (
        <>
          <h2 style={{ marginTop: 18 }}>{database ? 'Database credential' : 'Credentials per protocol'}</h2>
          <CredentialBindings
            slots={slotProtocols.map((p) => ({ protocol: p, label: p === 'database' ? `Database (${engineName(t.engine)})` : protocolName(p) }))}
            current={t.credentials}
            credentials={credentials}
            onSave={saveBindings}
            onError={setErr}
          />
        </>
      )}

      {certProbe && (
        <Alert tone={certProbe.accepted ? 'ok' : 'danger'} onDismiss={() => setCertProbe(null)}>
          {certProbe.accepted ? `The target accepted a certificate from ${sshCA?.name ?? 'the authority'} for login user ${certProbe.login_user}.` : `${certProbe.error ?? 'certificate login failed'} (login user ${certProbe.login_user}).`}
        </Alert>
      )}
      {probe && (
        <>
          <h2>{database ? 'Connection test' : 'Probe result'}</h2>
          <dl className="kv">
            <dt>Resolved</dt><dd className="mono">{probe.probe.resolved_ip}</dd>
            {probed.map((p) => {
              const r = probe.probe.ports[p]
              if (!r) return null
              return (
                <span key={p} style={{ display: 'contents' }}>
                  <dt>{p === 'database' ? `${engineName(t.engine)} port ${port ?? enginePorts[t.engine ?? ''] ?? ''}`.trim() : protocolName(p)}</dt>
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
          {host && (
            <button className="btn" onClick={() => void doProbe()} disabled={probing}>{probing ? 'Probing…' : 'Probe'}</button>
          )}
          {/* 2026-11-11: a database could not be checked before people
              tried it. The test reaches its port from the gateway; the
              database protocols start TLS inside themselves, so that is
              what it says. */}
          {database && (
            <button className="btn" onClick={() => void doProbe()} disabled={probing} title="Reaches the database port from the gateway">{probing ? 'Testing…' : 'Test connection'}</button>
          )}
          {canTrust && (
            <button className="btn primary" onClick={() => setConfirm('trust')}>Trust host key</button>
          )}
          {sshCA && t.host_key_status === 'trusted' && (
            <button className="btn" onClick={() => void testCertificate()} disabled={certProbing} title="Signs in once with a certificate from the bound authority, then disconnects">{certProbing ? 'Testing…' : 'Test certificate login'}</button>
          )}
          <button className="btn" onClick={() => setEditing(true)}>Edit</button>
          <button className="btn" disabled={toggling} onClick={toggleStatus} title={t.status === 'active' ? 'Open sessions on it end' : undefined}>{t.status === 'active' ? (toggling ? 'Disabling…' : 'Disable') : toggling ? 'Enabling…' : 'Enable'}</button>
          <button className="btn ghost" onClick={onClose}>Close</button>
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
              {t.host_key_status === 'changed' && <Alert tone="danger">Replaces a previously trusted key. Confirm the change with the machine's owner first.</Alert>}
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
      {trustCert && (
        <Confirm
          title={`Accept the new ${trustCert.protocol === 'rdp' ? 'RDP' : 'WinRM'} certificate?`}
          body={
            <div>
              <p>Zanskar will only connect to <strong>{t.name}</strong> over {trustCert.protocol === 'rdp' ? 'RDP' : 'WinRM'} when it presents this certificate:</p>
              <p className="mono" style={{ wordBreak: 'break-all' }}>{trustCert.seen}</p>
              <Alert tone="danger">This replaces the pinned certificate {trustCert.pinned}. Only proceed if you confirmed the change with the machine's owner.</Alert>
            </div>
          }
          confirmLabel="Accept"
          danger
          onClose={() => setTrustCert(null)}
          onConfirm={async () => {
            onChanged(await api.post<Target>(`/targets/${t.id}/certificate/trust`, { protocol: trustCert.protocol, fingerprint: trustCert.seen }))
          }}
        />
      )}
      {confirm === 'delete' && <DeleteAsset name={t.name} path={`/targets/${t.id}`} onClose={() => setConfirm(null)} onDeleted={onDeleted} />}
    </Modal>
  )
}

/**
 * BlockedDependencies lists what the application's sessions were refused,
 * newest first, each with what asked and from which page: a private host is
 * allowed in one click (it joins the private hosts); a page someone tried to
 * open is an endpoint's business; a loopback, link-local or metadata address
 * can never be allowed and is marked. What is allowed already is left out.
 */
function BlockedDependencies({ target, items, onAllow, onClear }: { target: Target; items: DependencyRefusal[] | null; onAllow: (hostport: string) => void; onClear: () => void }) {
  if (items === null) return <span className="muted">Loading…</span>
  const allowed = new Set(target.app_private?.hosts ?? [])
  const shown = items.filter((x) => !allowed.has(`${x.host}:${x.port}`))
  if (shown.length === 0) return <span className="muted">Nothing refused</span>
  return (
    <>
      <table className="compact blocked">
        <thead>
          <tr><th>Host</th><th>What</th><th>From</th><th>Seen</th><th aria-label="action"></th></tr>
        </thead>
        <tbody>
          {shown.map((x) => {
            const hostport = `${x.host}:${x.port}`
            const page = x.why === 'not an origin of the application'
            const never = x.why !== 'private' && !page
            return (
              <tr key={`${hostport}|${x.why}|${x.what}|${x.from}`}>
                <td className="mono">{hostport}</td>
                <td>{x.what}</td>
                <td className="muted from">{x.from || '—'}</td>
                <td className="muted">{x.count} × · {fmtTime(x.last_seen)}</td>
                <td>
                  {x.why === 'private' && <button className="btn sm" onClick={() => onAllow(hostport)} title="allow this private host for the application's dependencies">Allow</button>}
                  {page && <span className="muted" title="someone tried to open a page there; an endpoint would allow it">not an endpoint</span>}
                  {never && <StateIcon state="warn" label={`Never allowed: ${x.why}`} />}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <a href="#clear" className="muted" onClick={(e) => { e.preventDefault(); onClear() }}>Clear</a>
    </>
  )
}
