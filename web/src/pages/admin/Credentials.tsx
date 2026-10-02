import { useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Credential, CredentialType } from '../../api/types'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead } from '../../components/ui'
import { useList } from './lib'
import { CAInstall, CASetup, DEFAULT_CERT_TTL, parsePrincipals } from './SSHCA'

const types: { v: CredentialType; label: string }[] = [
  { v: 'password', label: 'Password' },
  { v: 'ssh_key', label: 'SSH private key' },
  { v: 'ssh_ca', label: 'SSH certificate authority' },
  { v: 'domain', label: 'Windows domain account' },
  { v: 'ec2_instance_connect', label: 'EC2 Instance Connect' },
]
function inUse(c: Credential) {
  return (c.in_use_by?.targets ?? 0) + (c.in_use_by?.autoscaling_groups ?? 0)
}

export function Credentials() {
  const { items, err, setErr, reload } = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [rotating, setRotating] = useState<Credential | null>(null)
  const [deleting, setDeleting] = useState<Credential | null>(null)
  const [generated, setGenerated] = useState<Credential | null>(null)
  const [ca, setCa] = useState<Credential | null>(null)

  return (
    <>
      <PageHead title="Credentials" lead="How Zanskar authenticates to targets. Secrets are sealed on save and never shown again; only public keys are displayed.">
        <button className="btn primary" onClick={() => setAdding(true)}>Add credential</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {generated && generated.type === 'ssh_ca' && (
        <Alert tone="ok">
          Certificate authority <strong>{generated.name}</strong> created; the private key is sealed and never shown. Targets trust it with:
          <div style={{ marginTop: 8 }}><CAInstall credential={generated} /></div>
        </Alert>
      )}
      {generated && generated.type !== 'ssh_ca' && (
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
                  <td>{c.type === 'ssh_ca' ? 'ssh certificate authority' : c.type}</td>
                  <td>{c.mode.replace(/_/g, ' ')}</td>
                  <td className="mono">{c.domain ? `${c.domain}\\` : ''}{c.username ?? <span className="muted">—</span>}</td>
                  <td className="mono muted" title={c.public_key}>{c.public_key ? c.public_key.slice(0, 28) + '…' : '—'}</td>
                  <td>{c.has_secret ? <Badge tone="ok">secret stored</Badge> : <Badge>none</Badge>}</td>
                  <td className="muted">{c.rotated_at ? fmtTime(c.rotated_at) : 'never'}</td>
                  <td>{inUse(c)}</td>
                  <td className="actions">
                    {c.type === 'ssh_ca' && (
                      <button className="btn sm" onClick={() => setCa(c)}>Setup</button>
                    )}
                    {/* An authority is rotated in two steps from its Setup panel (ADR 0022); the in-place form does not apply. */}
                    {c.mode === 'vaulted' && c.type !== 'ec2_instance_connect' && c.type !== 'ssh_ca' && (
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
      {ca && (
        <CASetup
          credential={ca}
          onClose={() => setCa(null)}
          onSaved={(c) => {
            setCa(c)
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

/** Private keys larger than this are not keys; refuse before reading further. */
const MAX_KEY_FILE = 64 * 1024

function SecretFields({ type, f, set, put }: { type: CredentialType; f: Record<string, string>; set: (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void; put: (k: string, v: string) => void }) {
  const [fileNote, setFileNote] = useState<{ text: string; err?: boolean } | null>(null)
  // A key file is read in the browser and lands in the same field a pasted
  // key would; it travels sealed in the same request, nothing is uploaded on
  // its own (manual QA finding R6).
  const readKeyFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > MAX_KEY_FILE) {
      setFileNote({ text: `${file.name} is ${Math.round(file.size / 1024)} KB; a private key is a few KB. Choose the key file, not a certificate bundle or archive.`, err: true })
      return
    }
    file
      .text()
      .then((text) => {
        const trimmed = text.trim()
        if (!trimmed.startsWith('-----BEGIN')) {
          setFileNote({ text: `${file.name} does not look like a PEM key (no -----BEGIN line). PuTTY .ppk files must be exported as OpenSSH first (puttygen, Conversions).`, err: true })
          return
        }
        put('private_key', trimmed + '\n')
        setFileNote({ text: `Loaded ${file.name}${/ENCRYPTED|Proc-Type: 4,ENCRYPTED|aes|bcrypt/i.test(trimmed) ? '; it looks encrypted, enter the passphrase below' : ''}.` })
      })
      .catch(() => setFileNote({ text: `Could not read ${file.name}.`, err: true }))
  }
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
        <Field label={type === 'ssh_ca' ? 'CA private key (PEM)' : 'Private key (PEM)'} hint="OpenSSH, PKCS#8 or PKCS#1; encrypted keys need the passphrase below. Paste it, or choose the file.">
          <textarea id="c-private-key" value={f.private_key} onChange={set('private_key')} required placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
          <div className="actions" style={{ marginTop: 6 }}>
            <input id="c-private-key-file" type="file" accept=".pem,.key,.pub,.txt,application/x-pem-file,text/plain" hidden onChange={readKeyFile} />
            <button type="button" className="btn sm" onClick={() => document.getElementById('c-private-key-file')?.click()}>Choose key file…</button>
            {fileNote && <span className="muted" style={fileNote.err ? { color: 'var(--danger)' } : undefined}>{fileNote.text}</span>}
          </div>
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
  const [f, setF] = useState<Record<string, string>>({ name: '', type: 'password', username: '', domain: '', password: '', private_key: '', passphrase: '', ttl: '', principals: '' })
  const [generate, setGenerate] = useState(false)
  // A certificate authority is normally generated here; pasting an existing
  // CA key is the exception.
  const [generateCA, setGenerateCA] = useState(true)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value })
  const put = (k: string, v: string) => setF({ ...f, [k]: v })
  // Every credential created here is vaulted: Zanskar holds the secret and
  // users never see it. "User supplied" is not a credential but a choice on
  // a target's slot (manual QA finding R35).
  const type = f.type as CredentialType
  const mode = 'vaulted'
  const needsSecret = type !== 'ec2_instance_connect'
  const needsUser = type !== 'ssh_ca'
  const isCA = type === 'ssh_ca'

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      if (type === 'ssh_key' && generate) {
        const c = await api.post<Credential>('/credentials/generate-ssh-key', { name: f.name.trim(), username: f.username.trim() })
        onSaved(c, true)
        return
      }
      const body: Record<string, unknown> = { name: f.name.trim(), type, mode }
      if (needsUser || (isCA && f.username.trim())) body.username = f.username.trim()
      if (type === 'domain') body.domain = f.domain.trim()
      if (isCA) {
        const n = f.ttl.trim() ? Number(f.ttl) : 0
        if (f.ttl.trim() && (!Number.isInteger(n) || n < 60 || n > 3600)) {
          setErr('certificate lifetime must be 60-3600 seconds, or blank for the default')
          return
        }
        if (n) body.certificate_ttl_seconds = n
        const principals = parsePrincipals(f.principals)
        if (principals.length) body.certificate_principals = principals
      }
      if (needsSecret && !(isCA && generateCA)) {
        if (type === 'password' || type === 'domain') body.password = f.password
        else {
          body.private_key = f.private_key
          if (f.passphrase) body.private_key_passphrase = f.passphrase
        }
      }
      const c = await api.post<Credential>('/credentials', body)
      onSaved(c, isCA && generateCA)
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
          <Field label="Type" hint="Zanskar stores the secret; users never see it. To let users type their own login instead, choose “User supplied” on the target's credential slot.">
            <select id="c-type" value={f.type} onChange={set('type')}>
              {types.map((t) => (
                <option key={t.v} value={t.v}>{t.label}</option>
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
        {type === 'ssh_key' && (
          <div className="field inline">
            <input id="c-generate" type="checkbox" checked={generate} onChange={(e) => setGenerate(e.target.checked)} />
            <label htmlFor="c-generate">Generate an ed25519 key for me (you will only see the public half)</label>
          </div>
        )}
        {isCA && (
          <>
            <p className="muted" style={{ marginTop: 0 }}>
              Keyless SSH: each session gets a certificate signed by this authority, valid for minutes, and targets trust one public key instead of holding a key per gateway. The recommended way to reach Linux targets.
            </p>
            <div className="form-grid">
              <Field label="Login user" hint="Blank: each person logs in as their own Zanskar username. Set it to make everyone use one account, e.g. deploy.">
                <input id="c-username" value={f.username} onChange={set('username')} placeholder="(each user as themselves)" />
              </Field>
              <Field label="Certificate lifetime (seconds)" hint={`Blank = ${DEFAULT_CERT_TTL}; 60-3600.`}>
                <input id="c-ttl" inputMode="numeric" value={f.ttl} onChange={set('ttl')} placeholder={String(DEFAULT_CERT_TTL)} />
              </Field>
            </div>
            <Field label="Allowed login users" hint="One per line. Blank = any login user.">
              <textarea id="c-principals" value={f.principals} onChange={set('principals')} placeholder={'deploy\nops'} style={{ minHeight: 50 }} />
            </Field>
            <div className="field inline">
              <input id="c-generate-ca" type="checkbox" checked={generateCA} onChange={(e) => setGenerateCA(e.target.checked)} />
              <label htmlFor="c-generate-ca">Generate an ed25519 authority key for me (the private key is sealed and never shown)</label>
            </div>
          </>
        )}
        {needsSecret && !(type === 'ssh_key' && generate) && !(isCA && generateCA) && <SecretFields type={type} f={f} set={set} put={put} />}
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy}>Create</button>
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
  const put = (k: string, v: string) => setF({ ...f, [k]: v })
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
        <SecretFields type={credential.type} f={f} set={set} put={put} />
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy}>Rotate</button>
        </div>
      </form>
    </Modal>
  )
}
