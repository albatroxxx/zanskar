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
  const daysLeft = a ? Math.floor((new Date(a.not_after).getTime() - now) / DAY) : 0
  const fallback = status.file_hint ? 'the certificate from the environment file' : 'its self-signed certificate'

  return (
    <div className="card">
      <h2>TLS certificate</h2>
      {status.mode === 'proxy' ? (
        <p className="muted">TLS is terminated by the proxy in front of the gateway (ZANSKAR_TLS_MODE=proxy); manage the certificate there. To have Zanskar serve TLS itself, set ZANSKAR_TLS_MODE=managed and restart.</p>
      ) : (
        <>
          <p className="muted">What browsers see when they connect. An uploaded certificate applies to the next connection, no restart. Until one is uploaded the gateway serves {status.file_hint ? 'the certificate from the environment file' : 'a self-signed certificate: browsers warn about it, and the SHA-256 below is what to check on first visit'}.</p>
          {err && <Alert tone="danger">{err}</Alert>}
          {ok && <Alert tone="ok">{ok}</Alert>}
          {a && (
            <dl className="kv">
              <dt>Serving</dt><dd>{sourceBadge(a)}</dd>
              <dt>Subject</dt><dd className="mono">{a.subject}</dd>
              {a.issuer !== a.subject && (
                <>
                  <dt>Issuer</dt><dd className="mono">{a.issuer}</dd>
                </>
              )}
              <dt>Names</dt><dd className="mono">{a.hosts.join(', ') || '—'}</dd>
              <dt>Valid until</dt>
              <dd>
                {fmtTime(a.not_after)} {daysLeft < 0 ? <Badge tone="danger">expired</Badge> : daysLeft < 30 ? <Badge tone="warn">{daysLeft} days left</Badge> : null}
              </dd>
              <dt>SHA-256</dt><dd className="mono" style={{ wordBreak: 'break-all' }}>{a.fingerprint}</dd>
            </dl>
          )}
          <h3 style={{ marginTop: 16 }}>Upload a certificate</h3>
          <p className="muted">PEM files: the certificate (with any intermediates after it) and its unencrypted private key. The key is sealed by the master key and never shown again.</p>
          <div className="form-grid">
            <Field label="Certificate (PEM)">
              <textarea id="tls-cert" value={certPEM} onChange={(e) => setCertPEM(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
              <input type="file" accept=".pem,.crt,.cer" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0], setCertPEM)} />
            </Field>
            <Field label="Private key (PEM)">
              <textarea id="tls-key" value={keyPEM} onChange={(e) => setKeyPEM(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
              <input type="file" accept=".pem,.key" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0], setKeyPEM)} />
            </Field>
          </div>
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
                  <p>A new self-signed certificate is made for these names. It serves only while no uploaded or file certificate takes precedence; browsers will warn again and its fingerprint changes.</p>
                  <Field label="Names (one per line: host names and IPs users type)" hint="Blank keeps the names the gateway detected on start.">
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
