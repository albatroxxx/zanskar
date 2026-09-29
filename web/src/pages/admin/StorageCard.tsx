import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { StorageConfig, StorageStatus } from '../../api/types'
import { Alert, Badge, Confirm, Field } from '../../components/ui'

const empty: StorageConfig = { bucket: '', prefix: 'recordings/', region: '', endpoint: '', kms_key_id: '', auth: 'role', access_key_id: '', secret_access_key: '' }

/**
 * StorageCard moves recording storage to an S3-compatible bucket from the
 * console and back (QA finding R18). A configuration is saved only after a
 * probe wrote, read and deleted an object with it; the next session then
 * records there, no restart. Existing local recordings can be moved in the
 * background.
 */
export function StorageCard() {
  const [status, setStatus] = useState<StorageStatus | null>(null)
  const [f, setF] = useState<StorageConfig>(empty)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirm] = useState<'reset' | 'move' | null>(null)
  const set = (k: keyof StorageConfig) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value })

  const load = () =>
    api
      .get<StorageStatus>('/admin/storage')
      .then((s) => {
        setStatus(s)
        if (s.active && s.source === 'console') setF({ ...empty, ...s.active, access_key_id: '', secret_access_key: '' })
      })
      .catch((e) => setErr(errorMessage(e)))
  useEffect(() => {
    void load()
  }, [])
  // While a move runs, follow its progress.
  useEffect(() => {
    if (!status?.move.running) return
    const t = setInterval(() => void load(), 2000)
    return () => clearInterval(t)
  }, [status?.move.running])

  const run = async (fn: () => Promise<unknown>, done: string) => {
    setErr('')
    setOk('')
    setBusy(true)
    try {
      await fn()
      await load()
      setOk(done)
    } catch (e) {
      setErr(errorMessage(e))
      throw e
    } finally {
      setBusy(false)
    }
  }
  if (!status) return null
  const body = { ...f, prefix: f.prefix || 'recordings/' }
  const local = status.counts.local ?? 0
  const activeBucket = status.active ? `s3://${status.active.bucket}` : ''
  const elsewhere = Object.entries(status.counts).filter(([k]) => k !== 'local' && k !== activeBucket).reduce((n, [, v]) => n + v, 0)

  return (
    <div className="card">
      <h2>Recording storage</h2>
      <p className="muted">Where session recordings are written. New recordings go to the active store; every recording is read from wherever it was written.</p>
      {err && <Alert tone="danger">{err}</Alert>}
      {ok && <Alert tone="ok">{ok}</Alert>}
      <dl className="kv">
        <dt>Active</dt>
        <dd>
          {status.active ? (
            <>
              <span className="mono">s3://{status.active.bucket}/{status.active.prefix}</span>{' '}
              {status.source === 'console' ? <Badge tone="accent">Set in console</Badge> : <Badge>From ZANSKAR_RECORDINGS_S3_*</Badge>}
              {status.active.endpoint && <span className="muted"> · {status.active.endpoint}</span>}
              {status.active.auth === 'keys' && <span className="muted"> · access key {status.active.access_key_id}</span>}
            </>
          ) : (
            <>
              <span>local directory</span> <Badge>Default</Badge>
            </>
          )}
        </dd>
        <dt>Recordings</dt>
        <dd>{Object.entries(status.counts).map(([k, v]) => `${v} in ${k}`).join(', ') || 'none yet'}</dd>
      </dl>
      {elsewhere > 0 && <Alert tone="warn">{elsewhere} recording{elsewhere === 1 ? '' : 's'} sit in a bucket that is no longer active and cannot be played until that bucket is configured again.</Alert>}
      <h3 style={{ marginTop: 16 }}>S3-compatible bucket</h3>
      <div className="form-grid">
        <Field label="Bucket"><input id="st-bucket" value={f.bucket} onChange={set('bucket')} placeholder="my-recordings" /></Field>
        <Field label="Key prefix" hint="folder inside the bucket"><input id="st-prefix" value={f.prefix} onChange={set('prefix')} /></Field>
        <Field label="Region" hint="blank: the SDK's default"><input id="st-region" value={f.region ?? ''} onChange={set('region')} placeholder="eu-west-1" /></Field>
        <Field label="Endpoint" hint="only for MinIO, Ceph and the like; path-style addressing is used"><input id="st-endpoint" value={f.endpoint ?? ''} onChange={set('endpoint')} placeholder="https://minio.internal:9000" /></Field>
        <Field label="KMS key" hint="blank: AES-256 server-side encryption"><input id="st-kms" value={f.kms_key_id ?? ''} onChange={set('kms_key_id')} /></Field>
        <Field label="Credentials" hint={f.auth === 'role' ? 'the instance role, environment or shared config the gateway runs with' : 'a static access key; the secret is sealed by the master key and never shown again'}>
          <select id="st-auth" value={f.auth} onChange={set('auth')}>
            <option value="role">Instance role / SDK default</option>
            <option value="keys">Access key</option>
          </select>
        </Field>
        {f.auth === 'keys' && (
          <>
            <Field label="Access key ID" hint={status.source === 'console' && status.active?.auth === 'keys' ? 'blank keeps the stored key' : undefined}><input id="st-akid" value={f.access_key_id ?? ''} onChange={set('access_key_id')} autoComplete="off" placeholder={status.source === 'console' ? status.active?.access_key_id : undefined} /></Field>
            <Field label="Secret access key" hint={status.active?.secret_set && status.source === 'console' ? 'blank keeps the stored secret' : undefined}><input id="st-secret" type="password" value={f.secret_access_key ?? ''} onChange={set('secret_access_key')} autoComplete="new-password" /></Field>
          </>
        )}
      </div>
      <div className="actions">
        <button className="btn" disabled={busy || !f.bucket} onClick={() => void run(() => api.post('/admin/storage/test', body), 'The bucket accepted a probe object: written, read back and deleted.').catch(() => {})}>Test</button>
        <button className="btn primary" disabled={busy || !f.bucket} onClick={() => void run(() => api.put('/admin/storage', body), 'Saved. The next session records to the bucket.').catch(() => {})}>Save and use</button>
        {status.source === 'console' && <button className="btn" disabled={busy} onClick={() => setConfirm('reset')}>Remove console setting</button>}
        {status.active && local > 0 && !status.move.running && <button className="btn" disabled={busy} onClick={() => setConfirm('move')}>Move {local} local recording{local === 1 ? '' : 's'} to the bucket…</button>}
      </div>
      {(status.move.running || status.move.finished_at) && (
        <p className="muted" style={{ marginTop: 8 }}>
          {status.move.running ? 'Moving…' : `Move finished ${fmtTime(status.move.finished_at)}:`} {status.move.moved} moved, {status.move.failed} failed{status.move.last_error ? ` (last error: ${status.move.last_error})` : ''}.
        </p>
      )}
      {confirm === 'reset' && (
        <Confirm
          title="Remove the console storage setting?"
          body={status.environment ? `New recordings go to the environment's bucket s3://${status.environment.bucket} again.` : 'New recordings go to the local directory again. Recordings already in the bucket stay readable only while a bucket is configured.'}
          confirmLabel="Remove"
          danger
          onClose={() => setConfirm(null)}
          onConfirm={() => run(() => api.del('/admin/storage'), 'Console setting removed.')}
        />
      )}
      {confirm === 'move' && (
        <Confirm
          title={`Move ${local} local recording${local === 1 ? '' : 's'}?`}
          body="Each finished recording is copied to the bucket, its digest checked, its record repointed and the local file removed. Recordings of sessions still running are left for a later move. This runs in the background and is written to the audit log when it finishes."
          confirmLabel="Move"
          onClose={() => setConfirm(null)}
          onConfirm={() => run(() => api.post('/admin/storage/move'), 'Move started.')}
        />
      )}
    </div>
  )
}
