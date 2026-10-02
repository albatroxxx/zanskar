import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { CertificateProbe, Credential, Target } from '../../api/types'
import { Alert, Badge, Confirm, Field, Modal } from '../../components/ui'

export const DEFAULT_CERT_TTL = 300

/**
 * The lines an administrator runs on a Linux target so sshd trusts
 * certificates from this authority. During a rotation both public keys are
 * written, one per line, which is how sshd overlaps authorities.
 */
export function caInstallSnippet(publicKeys: string[]): string {
  const keys = publicKeys.filter(Boolean)
  const write = keys.length === 1 ? `echo '${keys[0]}' > /etc/ssh/zanskar_ca.pub` : `printf '%s\\n' ${keys.map((k) => `'${k}'`).join(' ')} > /etc/ssh/zanskar_ca.pub`
  return [write, `echo 'TrustedUserCAKeys /etc/ssh/zanskar_ca.pub' > /etc/ssh/sshd_config.d/zanskar.conf`, `systemctl reload ssh 2>/dev/null || systemctl reload sshd`].join('\n')
}

/** The public keys a target should trust right now: the signing key plus a prepared next key. */
export function trustedKeys(c: Credential): string[] {
  return [c.public_key ?? '', c.rotation?.pending_public_key ?? ''].filter(Boolean)
}

export function parsePrincipals(text: string): string[] {
  return text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  return (
    <button
      type="button"
      className="btn sm"
      onClick={() => void navigator.clipboard?.writeText(text).then(() => setState('copied')).catch(() => setState('failed'))}
    >
      {state === 'copied' ? 'Copied' : state === 'failed' ? 'Select and copy' : (label ?? 'Copy')}
    </button>
  )
}

/**
 * CAInstall shows what a target needs to trust the authority: the public key
 * and the sshd configuration lines. Shown after a CA is created and from the
 * setup panel; there is no secret in it.
 */
export function CAInstall({ credential }: { credential: Credential }) {
  const keys = trustedKeys(credential)
  const snippet = caInstallSnippet(keys)
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>
        Run this once on each Linux target, as root. It installs the authority's public key{keys.length > 1 ? 's (the current one and the prepared next one)' : ''} and tells sshd to trust
        certificates {keys.length > 1 ? 'they sign' : 'it signs'}. Older sshd without <code>sshd_config.d</code>: put the <code>TrustedUserCAKeys</code> line in <code>/etc/ssh/sshd_config</code> instead.
      </p>
      <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>{snippet}</pre>
      <div className="actions" style={{ marginTop: 8 }}>
        <CopyButton text={snippet} label="Copy commands" />
        <CopyButton text={keys.join('\n')} label={keys.length > 1 ? 'Copy public keys only' : 'Copy public key only'} />
      </div>
    </>
  )
}

/**
 * CARotation drives the two-phase key rotation (ADR 0022): prepare a next
 * key, install both public keys on targets and test them, cut over, then
 * remove the old key from targets and confirm. Every step is a separate,
 * confirmed action so a half-rotated fleet is always visible here.
 */
function CARotation({ credential, onChanged, onError }: { credential: Credential; onChanged: (c: Credential) => void; onError: (m: string) => void }) {
  const [confirm, setConfirm] = useState<'prepare' | 'cutover' | 'cancel' | 'retire' | null>(null)
  const pending = credential.rotation?.pending_public_key
  const retired = credential.rotation?.retired_public_key
  const step = async (fn: () => Promise<Credential>) => {
    try {
      onChanged(await fn())
    } catch (e) {
      onError(errorMessage(e))
      throw e
    }
  }
  return (
    <>
      <h3>Key rotation</h3>
      {!pending && !retired && (
        <p className="muted">
          Rotating the authority is two steps, so no session breaks on a host that has not learned the new key: prepare a next key and install both public keys on every target, then cut over. There is no schedule; rotate when the key may have been exposed or when policy says so.
        </p>
      )}
      {pending && (
        <Alert tone="warn">
          A next key is prepared{credential.rotation?.pending_since ? ` (${fmtTime(credential.rotation.pending_since)})` : ''}. The install commands above now write both public keys. Once every target trusts the next key (test below), cut over; until then sessions keep using the current key.
        </Alert>
      )}
      {retired && (
        <Alert tone="warn">
          Cut over{credential.rotation?.retired_at ? ` on ${fmtTime(credential.rotation.retired_at)}` : ''}. Sessions now use the new key. Remove the old public key from each target's <code>/etc/ssh/zanskar_ca.pub</code> (the install commands above write only the new one), then confirm here.
          <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: '8px 0 0' }}>{retired}</pre>
        </Alert>
      )}
      <div className="actions">
        {!pending && <button type="button" className="btn" onClick={() => setConfirm('prepare')}>Prepare next key</button>}
        {pending && <button type="button" className="btn primary" onClick={() => setConfirm('cutover')}>Cut over to the next key</button>}
        {pending && <button type="button" className="btn" onClick={() => setConfirm('cancel')}>Discard next key</button>}
        {retired && <button type="button" className="btn" onClick={() => setConfirm('retire')}>Old key removed from targets</button>}
      </div>
      {confirm === 'prepare' && (
        <Confirm title="Prepare a next key?" body="A new ed25519 authority key is generated and sealed beside the current one. Nothing changes for sessions until you cut over." confirmLabel="Prepare" onClose={() => setConfirm(null)} onConfirm={() => step(() => api.post<Credential>(`/credentials/${credential.id}/rotate`, {}))} />
      )}
      {confirm === 'cutover' && (
        <Confirm title="Cut over to the next key?" body="From the next session on, certificates are signed with the next key. A target that does not trust it yet will refuse logins. Test every bound target first." confirmLabel="Cut over" danger onClose={() => setConfirm(null)} onConfirm={() => step(() => api.post<Credential>(`/credentials/${credential.id}/rotate/cut-over`))} />
      )}
      {confirm === 'cancel' && (
        <Confirm title="Discard the prepared key?" body="The next key is destroyed; targets that already trust it keep a harmless extra line." confirmLabel="Discard" danger onClose={() => setConfirm(null)} onConfirm={() => step(() => api.del<Credential>(`/credentials/${credential.id}/rotate`))} />
      )}
      {confirm === 'retire' && (
        <Confirm title="Old key removed from every target?" body="This only clears the reminder; Zanskar cannot check that the old public key is gone." confirmLabel="Confirm" onClose={() => setConfirm(null)} onConfirm={() => step(() => api.post<Credential>(`/credentials/${credential.id}/rotate/retire`))} />
      )}
    </>
  )
}

/**
 * CATargets lists the hosts whose SSH slot uses this authority and lets the
 * administrator test a certificate login on each: with the current key, or
 * with the prepared next key during a rotation.
 */
function CATargets({ credential }: { credential: Credential }) {
  const [targets, setTargets] = useState<Target[] | null>(null)
  const [results, setResults] = useState<Record<string, CertificateProbe | { error: string }>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const pending = !!credential.rotation?.pending_public_key
  useEffect(() => {
    api
      .get<{ items: Target[] }>('/targets?kind=host&limit=500')
      .then((p) => setTargets(p.items.filter((t) => t.credentials?.ssh === credential.id)))
      .catch(() => setTargets([]))
  }, [credential.id])
  const test = async (t: Target, key: 'current' | 'pending') => {
    setBusy(t.id + key)
    try {
      setResults((r) => ({ ...r, [t.id]: {} as CertificateProbe }))
      const res = await api.post<CertificateProbe>(`/targets/${t.id}/probe-certificate`, { key })
      setResults((r) => ({ ...r, [t.id]: res }))
    } catch (e) {
      setResults((r) => ({ ...r, [t.id]: { error: errorMessage(e) } }))
    } finally {
      setBusy(null)
    }
  }
  if (targets === null) return null
  return (
    <>
      <h3>Bound targets</h3>
      {targets.length === 0 ? (
        <p className="muted">No host uses this authority on its SSH slot yet. Bind it on a target, then test the login here.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Target</th><th>Host key</th><th>Certificate login</th><th></th></tr>
            </thead>
            <tbody>
              {targets.map((t) => {
                const r = results[t.id]
                return (
                  <tr key={t.id}>
                    <td><strong>{t.name}</strong> <span className="mono muted">{t.address}</span></td>
                    <td>{t.host_key_status === 'trusted' ? <Badge tone="ok">trusted</Badge> : <Badge tone="warn">{t.host_key_status}</Badge>}</td>
                    <td>
                      {r && 'accepted' in r && r.accepted && <Badge tone="ok">accepted as {r.login_user} ({r.key} key)</Badge>}
                      {r && 'accepted' in r && r.accepted === false && <span><Badge tone="danger">{r.reason?.replace(/_/g, ' ')}</Badge> <span className="muted">{r.error}</span></span>}
                      {r && 'error' in r && <span className="muted" style={{ color: 'var(--danger)' }}>{r.error}</span>}
                    </td>
                    <td className="actions">
                      <button type="button" className="btn sm" disabled={busy !== null || t.host_key_status !== 'trusted'} onClick={() => void test(t, 'current')}>{busy === t.id + 'current' ? 'Testing…' : 'Test'}</button>
                      {pending && <button type="button" className="btn sm" disabled={busy !== null || t.host_key_status !== 'trusted'} onClick={() => void test(t, 'pending')}>{busy === t.id + 'pending' ? 'Testing…' : 'Test next key'}</button>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

/**
 * CASetup is the panel for one certificate authority: how to install it on
 * targets, and its settings (fixed login user, certificate lifetime, principal
 * allowlist). Saving applies to the next session; nothing here touches the
 * sealed key.
 */
export function CASetup({ credential, onClose, onSaved }: { credential: Credential; onClose: () => void; onSaved: (c: Credential) => void }) {
  const [username, setUsername] = useState(credential.username ?? '')
  const [ttl, setTtl] = useState(credential.certificate_ttl_seconds ? String(credential.certificate_ttl_seconds) : '')
  const [principals, setPrincipals] = useState((credential.certificate_principals ?? []).join('\n'))
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    setOk('')
    const n = ttl.trim() ? Number(ttl) : 0
    if (ttl.trim() && (!Number.isInteger(n) || n < 60 || n > 3600)) {
      setErr('certificate lifetime must be 60-3600 seconds, or blank for the default')
      return
    }
    setBusy(true)
    try {
      const c = await api.patch<Credential>(`/credentials/${credential.id}`, {
        username: username.trim(),
        certificate_ttl_seconds: n,
        certificate_principals: parsePrincipals(principals),
      })
      setOk('Saved. Applies to the next session.')
      onSaved(c)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const bound = (credential.in_use_by?.targets ?? 0) + (credential.in_use_by?.autoscaling_groups ?? 0)

  return (
    <Modal title={`${credential.name}: certificate authority`} onClose={onClose} width={680}>
      {err && <Alert tone="danger">{err}</Alert>}
      {ok && <Alert tone="ok">{ok}</Alert>}
      <h3 style={{ marginTop: 0 }}>Install on targets</h3>
      <CAInstall credential={credential} />
      <p className="muted">
        Bound to {bound} {bound === 1 ? 'target or group' : 'targets and groups'}. Each session gets a fresh certificate signed by this authority; nothing is stored on the target and there is no key to rotate there.
      </p>
      <CATargets credential={credential} />
      <CARotation credential={credential} onChanged={onSaved} onError={setErr} />
      <h3>Settings</h3>
      <form onSubmit={save}>
        <div className="form-grid">
          <Field label="Login user" hint="Blank: each person logs in as their own Zanskar username. Set it to make everyone use one account, e.g. deploy.">
            <input id="ca-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="(each user as themselves)" />
          </Field>
          <Field label="Certificate lifetime (seconds)" hint={`Blank = ${DEFAULT_CERT_TTL}. It only needs to outlive the connection handshake; 60-3600.`}>
            <input id="ca-ttl" inputMode="numeric" value={ttl} onChange={(e) => setTtl(e.target.value)} placeholder={String(DEFAULT_CERT_TTL)} />
          </Field>
        </div>
        <Field label="Allowed login users" hint="One per line. Blank = any. A connect for a login user not listed is refused before a certificate is minted.">
          <textarea id="ca-principals" value={principals} onChange={(e) => setPrincipals(e.target.value)} placeholder={'deploy\nops'} />
        </Field>
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Close</button>
          <button type="submit" className="btn primary" disabled={busy}>Save</button>
        </div>
      </form>
    </Modal>
  )
}
