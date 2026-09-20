import { useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Credential, CredentialMode, CredentialType } from '../../api/types'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead } from '../../components/ui'
import { useList } from './lib'

const types: { v: CredentialType; label: string }[] = [
  { v: 'password', label: 'Password' },
  { v: 'ssh_key', label: 'SSH private key' },
  { v: 'ssh_ca', label: 'SSH certificate authority' },
  { v: 'domain', label: 'Windows domain account' },
  { v: 'ec2_instance_connect', label: 'EC2 Instance Connect' },
]
const modes: { v: CredentialMode; label: string; hint: string }[] = [
  { v: 'vaulted', label: 'Vaulted', hint: 'Zanskar stores the secret; users never see it' },
  { v: 'user_supplied', label: 'User supplied', hint: 'the user types their own credentials at connect time' },
  { v: 'passthrough', label: 'Passthrough', hint: 'forward the user’s directory login (not yet available)' },
]

function inUse(c: Credential) {
  return (c.in_use_by?.targets?.length ?? 0) + (c.in_use_by?.autoscaling_groups?.length ?? 0)
}

export function Credentials() {
  const { items, err, setErr, reload } = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [rotating, setRotating] = useState<Credential | null>(null)
  const [deleting, setDeleting] = useState<Credential | null>(null)
  const [generated, setGenerated] = useState<Credential | null>(null)

  return (
    <>
      <PageHead title="Credentials" lead="How Zanskar authenticates to targets. Secrets are sealed on save and never shown again; only public keys are displayed.">
        <button className="btn primary" onClick={() => setAdding(true)}>Add credential</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {generated && (
        <Alert tone="ok">
          Key pair created for <strong>{generated.name}</strong>. Add this public key to the target's <code>authorized_keys</code>:
          <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: '8px 0 0' }}>{generated.public_key}</pre>
        </Alert>
      )}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No credentials yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Mode</th>
                <th>Username</th>
                <th>Public key</th>
                <th>Secret</th>
                <th>Rotated</th>
                <th>In use</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id}>
                  <td><strong>{c.name}</strong></td>
                  <td>{c.type}</td>
                  <td>{c.mode}</td>
                  <td className="mono">{c.domain ? `${c.domain}\\` : ''}{c.username ?? <span className="muted">—</span>}</td>
                  <td className="mono muted" title={c.public_key}>{c.public_key ? c.public_key.slice(0, 28) + '…' : '—'}</td>
                  <td>{c.has_secret ? <Badge tone="ok">secret stored</Badge> : <Badge>none</Badge>}</td>
                  <td className="muted">{c.rotated_at ? fmtTime(c.rotated_at) : 'never'}</td>
                  <td>{inUse(c)}</td>
                  <td className="actions">
                    {c.mode === 'vaulted' && c.type !== 'ec2_instance_connect' && (
                      <button className="btn sm" onClick={() => setRotating(c)}>Rotate</button>
                    )}
                    <button className="btn sm danger" onClick={() => setDeleting(c)} disabled={inUse(c) > 0} title={inUse(c) > 0 ? 'unassign it from targets first' : ''}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {adding && (
        <CredentialForm
          onClose={() => setAdding(false)}
          onSaved={(c, gen) => {
            setAdding(false)
            if (gen) setGenerated(c)
            void reload()
          }}
        />
      )}
      {rotating && (
        <RotateForm
          credential={rotating}
          onClose={() => setRotating(null)}
          onSaved={() => {
            setRotating(null)
            void reload()
          }}
        />
      )}
      {deleting && (
        <Confirm
          title={`Delete ${deleting.name}?`}
          body="The sealed secret is destroyed. This cannot be undone."
          confirmLabel="Delete"
          danger
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            try {
              await api.del(`/credentials/${deleting.id}`)
              void reload()
            } catch (e) {
              setErr(errorMessage(e))
              throw e
            }
          }}
        />
      )}
    </>
  )
}

function SecretFields({ type, f, set }: { type: CredentialType; f: Record<string, string>; set: (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void }) {
  if (type === 'password' || type === 'domain') {
    return (
      <Field label="Password">
        <input id="c-password" type="password" autoComplete="new-password" value={f.password} onChange={set('password')} required />
      </Field>
    )
  }
  if (type === 'ssh_key' || type === 'ssh_ca') {
    return (
      <>
        <Field label={type === 'ssh_ca' ? 'CA private key (PEM)' : 'Private key (PEM)'} hint="OpenSSH, PKCS#8 or PKCS#1; encrypted keys need the passphrase below">
          <textarea id="c-private-key" value={f.private_key} onChange={set('private_key')} required placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
        </Field>
        <Field label="Passphrase (if the key is encrypted)">
          <input id="c-passphrase" type="password" autoComplete="off" value={f.passphrase} onChange={set('passphrase')} />
        </Field>
      </>
    )
  }
  return null
}

function CredentialForm({ onClose, onSaved }: { onClose: () => void; onSaved: (c: Credential, generated: boolean) => void }) {
  const [f, setF] = useState<Record<string, string>>({ name: '', type: 'password', mode: 'vaulted', username: '', domain: '', password: '', private_key: '', passphrase: '' })
  const [generate, setGenerate] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value })
  const type = f.type as CredentialType
  const mode = f.mode as CredentialMode
  const needsSecret = mode === 'vaulted' && type !== 'ec2_instance_connect'
  const needsUser = mode === 'vaulted' && type !== 'ssh_ca'

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      if (type === 'ssh_key' && mode === 'vaulted' && generate) {
        const c = await api.post<Credential>('/credentials/generate-ssh-key', { name: f.name.trim(), username: f.username.trim() })
        onSaved(c, true)
        return
      }
      const body: Record<string, string> = { name: f.name.trim(), type, mode }
      if (needsUser) body.username = f.username.trim()
      if (type === 'domain') body.domain = f.domain.trim()
      if (needsSecret) {
        if (type === 'password' || type === 'domain') body.password = f.password
        else {
          body.private_key = f.private_key
          if (f.passphrase) body.private_key_passphrase = f.passphrase
        }
      }
      const c = await api.post<Credential>('/credentials', body)
      onSaved(c, false)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title="Add credential" onClose={onClose} width={600}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form onSubmit={submit}>
        <Field label="Name">
          <input id="c-name" value={f.name} onChange={set('name')} required autoFocus />
        </Field>
        <div className="form-grid">
          <Field label="Type">
            <select id="c-type" value={f.type} onChange={set('type')}>
              {types.map((t) => (
                <option key={t.v} value={t.v}>{t.label}</option>
              ))}
            </select>
          </Field>
          <Field label="Mode" hint={modes.find((m) => m.v === mode)?.hint}>
            <select id="c-mode" value={f.mode} onChange={set('mode')} disabled={type === 'ec2_instance_connect'}>
              {modes.map((m) => (
                <option key={m.v} value={m.v}>{m.label}</option>
              ))}
            </select>
          </Field>
        </div>
        {needsUser && (
          <div className="form-grid">
            <Field label="Username on the target">
              <input id="c-username" value={f.username} onChange={set('username')} required />
            </Field>
            {type === 'domain' && (
              <Field label="Domain">
                <input id="c-domain" value={f.domain} onChange={set('domain')} required />
              </Field>
            )}
          </div>
        )}
        {type === 'ssh_key' && mode === 'vaulted' && (
          <div className="field inline">
            <input id="c-generate" type="checkbox" checked={generate} onChange={(e) => setGenerate(e.target.checked)} />
            <label htmlFor="c-generate">Generate an ed25519 key for me (you will only see the public half)</label>
          </div>
        )}
        {needsSecret && !(type === 'ssh_key' && generate) && <SecretFields type={type} f={f} set={set} />}
        {mode === 'passthrough' && <Alert tone="warn">Passthrough is planned for the identity provider phase; this credential cannot be used to connect yet.</Alert>}
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>Create</button>
        </div>
      </form>
    </Modal>
  )
}

function RotateForm({ credential, onClose, onSaved }: { credential: Credential; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<Record<string, string>>({ password: '', private_key: '', passphrase: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value })
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const body: Record<string, string> = {}
      if (credential.type === 'password' || credential.type === 'domain') body.password = f.password
      else {
        body.private_key = f.private_key
        if (f.passphrase) body.private_key_passphrase = f.passphrase
      }
      await api.post(`/credentials/${credential.id}/rotate`, body)
      onSaved()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title={`Rotate ${credential.name}`} onClose={onClose} width={560}>
      {err && <Alert tone="danger">{err}</Alert>}
      <p className="muted" style={{ marginTop: 0 }}>The new secret replaces the old one immediately for every target using this credential.</p>
      <form onSubmit={submit}>
        <SecretFields type={credential.type} f={f} set={set} />
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>Rotate</button>
        </div>
      </form>
    </Modal>
  )
}
