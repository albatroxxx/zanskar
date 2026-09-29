import { useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import type { Credential } from '../../api/types'
import { Alert, Field, Modal } from '../../components/ui'

export const DEFAULT_CERT_TTL = 300

/** The lines an administrator runs on a Linux target so sshd trusts certificates from this authority. */
export function caInstallSnippet(publicKey: string): string {
  return [
    `echo '${publicKey}' > /etc/ssh/zanskar_ca.pub`,
    `echo 'TrustedUserCAKeys /etc/ssh/zanskar_ca.pub' > /etc/ssh/sshd_config.d/zanskar.conf`,
    `systemctl reload ssh 2>/dev/null || systemctl reload sshd`,
  ].join('\n')
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
  const pub = credential.public_key ?? ''
  const snippet = caInstallSnippet(pub)
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>
        Run this once on each Linux target, as root. It installs the authority's public key and tells sshd to trust
        certificates it signs. Older sshd without <code>sshd_config.d</code>: put the <code>TrustedUserCAKeys</code> line in <code>/etc/ssh/sshd_config</code> instead.
      </p>
      <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>{snippet}</pre>
      <div className="actions" style={{ marginTop: 8 }}>
        <CopyButton text={snippet} label="Copy commands" />
        <CopyButton text={pub} label="Copy public key only" />
      </div>
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
          <button className="btn primary" disabled={busy}>Save</button>
        </div>
      </form>
    </Modal>
  )
}
