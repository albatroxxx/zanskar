import { useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { dbTLS, engineName, fmtTime } from '../../api/format'
import type { CertificateProbe, Credential, Protocol, Target } from '../../api/types'
import { Alert, Badge, Confirm, Modal, Tags } from '../../components/ui'
import { hostKeyBadge, protocols, type ProbeWire } from './lib'
import { CredentialBindings, type BindingChange } from './Bindings'
import { TargetForm, targetBody } from './TargetForm'

interface ProbeResponse { target: Target; probe: ProbeWire; host_key_status: string; host_key_fingerprint: string | null; host_key_changed_from?: string | null }

/**
 * TargetDetail is the drawer for one host or database. A host shows its
 * probe state, host key and per-protocol credentials; a database shows its
 * engine, endpoint and TLS settings and a single credential slot, since
 * probing and host keys do not apply to it.
 */
export function TargetDetail({ target, credentials, onClose, onChanged, onDeleted, onError }: { target: Target; credentials: Credential[]; onClose: () => void; onChanged: (t: Target) => void; onDeleted: () => void; onError: (m: string) => void }) {
  const [editing, setEditing] = useState(false)
  const [probe, setProbe] = useState<ProbeResponse | null>(null)
  const [probing, setProbing] = useState(false)
  const [certProbe, setCertProbe] = useState<CertificateProbe | null>(null)
  const [certProbing, setCertProbing] = useState(false)
  const [confirm, setConfirm] = useState<'trust' | 'delete' | null>(null)
  const [err, setErr] = useState('')
  const t = target
  const database = !!t.engine

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

  const toggleStatus = () => run(async () => onChanged(await api.put<Target>(`/targets/${t.id}`, targetBody(t, { status: t.status === 'active' ? 'disabled' : 'active' }))))

  // A certificate login test applies when the SSH slot holds an authority
  // and the host key is trusted; it is a real login, so it is a button, not
  // part of the ordinary probe.
  const sshCA = !database && t.credentials?.ssh ? credentials.find((c) => c.id === t.credentials.ssh && c.type === 'ssh_ca') : undefined
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
  const canTrust = !database && (t.host_key_status === 'pending' || t.host_key_status === 'changed') && !!fp
  const port = t.ports.database

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
        ) : (
          <>
            <dt>Address</dt><dd className="mono">{t.address}</dd>
            <dt>OS</dt><dd>{t.os_family}</dd>
          </>
        )}
        <dt>Status</dt><dd>{t.status}</dd>
        {!database && (
          <>
            <dt>Capabilities</dt><dd>{t.capabilities.length ? t.capabilities.join(', ') : <span className="muted">unprobed</span>}</dd>
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
        {!database && (
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

      <h2 style={{ marginTop: 18 }}>{database ? 'Database credential' : 'Credentials per protocol'}</h2>
      {/* A database target has one slot, the brokered "database" protocol;
          the host slots (ssh, rdp, vnc, winrm) do not apply to it. */}
      <CredentialBindings
        slots={(database ? (['database'] as Protocol[]) : protocols).map((p) => ({ protocol: p, label: p === 'database' ? `Database (${engineName(t.engine)})` : p.toUpperCase() }))}
        current={t.credentials}
        credentials={credentials}
        onSave={saveBindings}
        onError={setErr}
      />

      {certProbe && (
        <Alert tone={certProbe.accepted ? 'ok' : 'danger'}>
          {certProbe.accepted ? `The target accepted a certificate from ${sshCA?.name ?? 'the authority'} for login user ${certProbe.login_user}.` : `${certProbe.error ?? 'certificate login failed'} (login user ${certProbe.login_user}).`}
        </Alert>
      )}
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
          {!database && (
            <button className="btn" onClick={() => void doProbe()} disabled={probing}>{probing ? 'Probing…' : 'Probe'}</button>
          )}
          {canTrust && (
            <button className="btn primary" onClick={() => setConfirm('trust')}>Trust host key</button>
          )}
          {sshCA && t.host_key_status === 'trusted' && (
            <button className="btn" onClick={() => void testCertificate()} disabled={certProbing} title="Signs in once with a certificate from the bound authority, then disconnects">{certProbing ? 'Testing…' : 'Test certificate login'}</button>
          )}
          <button className="btn" onClick={() => setEditing(true)}>Edit</button>
          <button className="btn" onClick={() => void toggleStatus()}>{t.status === 'active' ? 'Disable' : 'Enable'}</button>
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
          body={`The ${database ? 'database' : 'target'} leaves every list and its credential bindings are removed; past sessions, recordings and audit events keep its name. Deletion is refused while a policy names it by id or a session is open on it.`}
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
