import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { TLSCertInfo, TLSStatus } from '../../api/types'
import { Alert, Badge, Confirm, Field } from '../../components/ui'

const DAY = 24 * 60 * 60 * 1000

function sourceBadge(c: TLSCertInfo) {
  switch (c.source) {
    case 'uploaded':
      return <Badge tone="accent">Uploaded</Badge>
    case 'file':
      return <Badge>From ZANSKAR_TLS_CERT</Badge>
    default:
      return <Badge tone="warn">Self-signed</Badge>
  }
}

/** CertFacts lists what a certificate says about itself; never its key. */
function CertFacts({ c, now }: { c: TLSCertInfo; now: number }) {
  const daysLeft = Math.floor((new Date(c.not_after).getTime() - now) / DAY)
  return (
    <dl className="kv">
      <dt>Subject</dt><dd className="mono">{c.subject}</dd>
      {c.issuer !== c.subject && (
        <>
          <dt>Issuer</dt><dd className="mono">{c.issuer}</dd>
        </>
      )}
      <dt>Names</dt><dd className="mono">{c.hosts.join(', ') || '—'}</dd>
      <dt>Valid until</dt>
      <dd>
        {fmtTime(c.not_after)} {daysLeft < 0 ? <Badge tone="danger">expired</Badge> : daysLeft < 30 ? <Badge tone="warn">{daysLeft} days left</Badge> : null}
      </dd>
      <dt>SHA-256</dt><dd className="mono" style={{ wordBreak: 'break-all' }}>{c.fingerprint}</dd>
    </dl>
  )
}

/** PEMFields is the certificate-and-key pair an upload needs, typed or picked
 *  as files. (The key is `privateKey`: `key` is React's own prop name.) */
function PEMFields({ id, cert, privateKey, onCert, onKey }: { id: string; cert: string; privateKey: string; onCert: (v: string) => void; onKey: (v: string) => void }) {
  return (
    <div className="form-grid">
      <Field label="Certificate (PEM)">
        <textarea id={`${id}-cert`} value={cert} onChange={(e) => onCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        <input type="file" accept=".pem,.crt,.cer" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0], onCert)} />
      </Field>
      <Field label="Private key (PEM)">
        <textarea id={`${id}-key`} value={privateKey} onChange={(e) => onKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
        <input type="file" accept=".pem,.key" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0], onKey)} />
      </Field>
    </div>
  )
}

function readFile(file: File, cb: (text: string) => void) {
  const r = new FileReader()
  r.onload = () => cb(String(r.result ?? ''))
  r.readAsText(file)
}

/**
 * TLSCard shows the certificate the gateway serves and lets an administrator
 * replace it (ADR 0021). An upload applies to the next connection; removing
 * it falls back to the file certificate or the self-signed one. In proxy
 * mode there is nothing to manage here.
 */
export function TLSCard() {
  const [status, setStatus] = useState<TLSStatus | null>(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [certPEM, setCertPEM] = useState('')
  const [keyPEM, setKeyPEM] = useState('')
  const [hosts, setHosts] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirm] = useState<'reset' | 'regenerate' | null>(null)
  // Taken when the status loads rather than during render, so a render is pure.
  const [now, setNow] = useState(0)

  useEffect(() => {
    api
      .get<TLSStatus>('/admin/tls')
      .then((s) => {
        setStatus(s)
        setNow(Date.now())
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  const run = async (fn: () => Promise<TLSStatus>, done: string) => {
    setErr('')
    setOk('')
    setBusy(true)
    try {
      setStatus(await fn())
      setOk(done)
    } catch (e) {
      setErr(errorMessage(e))
      throw e
    } finally {
      setBusy(false)
    }
  }
  const upload = () =>
    run(
      () =>
        api.put<TLSStatus>('/admin/tls', { cert_pem: certPEM, key_pem: keyPEM }).then((s) => {
          setCertPEM('')
          setKeyPEM('')
          return s
        }),
      'Certificate uploaded and serving.',
    ).catch(() => {})

  if (!status) return null
  const a = status.active
  const fallback = status.file_hint ? 'the certificate from the environment file' : 'its self-signed certificate'

  return (
    <div className="card" id="settings-tls-certificate">
      <h2>TLS certificate</h2>
      {status.mode === 'proxy' ? (
        <p className="muted">Terminated by the proxy in front of the gateway (<code>ZANSKAR_TLS_MODE=proxy</code>).</p>
      ) : (
        <>
          {err && <Alert tone="danger">{err}</Alert>}
          {ok && <Alert tone="ok">{ok}</Alert>}
          {status.uploaded?.problem && (
            <Alert tone="warn">
              The uploaded certificate ({status.uploaded.subject}) is not in use: {status.uploaded.problem}. Upload a replacement below, or remove it.
            </Alert>
          )}
          {a && (
            <>
              <dl className="kv">
                <dt>Serving</dt><dd>{sourceBadge(a)}</dd>
              </dl>
              <CertFacts c={a} now={now} />
            </>
          )}
          <h3 style={{ marginTop: 16 }}>Upload a certificate</h3>
          <p className="muted">PEM: the certificate with its chain, and the unencrypted key.</p>
          <PEMFields id="tls" cert={certPEM} privateKey={keyPEM} onCert={setCertPEM} onKey={setKeyPEM} />
          <div className="actions">
            <button className="btn primary" disabled={busy || !certPEM.trim() || !keyPEM.trim()} onClick={() => void upload()}>Upload and serve</button>
            {status.uploaded && <button className="btn" disabled={busy} onClick={() => setConfirm('reset')}>Remove uploaded certificate</button>}
            <button className="btn" disabled={busy} onClick={() => setConfirm('regenerate')}>Regenerate self-signed…</button>
          </div>

          {confirm === 'reset' && (
            <Confirm
              title="Remove the uploaded certificate?"
              body={`The gateway goes back to ${fallback} on the next connection${status.file_hint ? '' : '; browsers will warn again'}.`}
              confirmLabel="Remove"
              danger
              onClose={() => setConfirm(null)}
              onConfirm={() => run(() => api.del<TLSStatus>('/admin/tls'), 'Uploaded certificate removed.')}
            />
          )}
          {confirm === 'regenerate' && (
            <Confirm
              title="Regenerate the self-signed certificate?"
              body={
                <div>
                  <p>Its fingerprint changes and browsers warn again.</p>
                  <Field label="Names (host names and IPs, one per line)" info="Left empty, the names detected when the gateway started.">
                    <textarea id="tls-hosts" value={hosts} onChange={(e) => setHosts(e.target.value)} placeholder={(status.generated?.hosts ?? []).join('\n')} />
                  </Field>
                </div>
              }
              confirmLabel="Regenerate"
              onClose={() => setConfirm(null)}
              onConfirm={() => run(() => api.post<TLSStatus>('/admin/tls/self-signed', { hosts: hosts.split('\n').map((h) => h.trim()).filter(Boolean) }), 'Self-signed certificate regenerated.')}
            />
          )}
        </>
      )}
    </div>
  )
}
