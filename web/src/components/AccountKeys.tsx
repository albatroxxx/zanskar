import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, errorMessage } from '../api/client'
import { fmtTime } from '../api/format'
import type { SecurityKey } from '../api/types'
import { createKey, keyError, keysInBrowser } from '../api/webauthn'
import { useAuth } from '../auth/AuthContext'
import { KeyButton } from './KeyButton'
import { Alert, Field } from './ui'

/**
 * AccountKeys is the account dialog's security keys and passkeys (ADR 0028):
 * each key with when it was added and last used, Add key, Rename, Remove, and
 * New recovery codes. Adding beside a second factor, removing, and new codes
 * ask for a fresh one; the step-up shows here, a code or a key, and the
 * action runs again once it is proved.
 */
export function AccountKeys() {
  const auth = useAuth()
  const [keys, setKeys] = useState<SecurityKey[] | null>(null)
  const [off, setOff] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null)
  const [codes, setCodes] = useState<string[]>([])
  // What a refusal asked for before the action can run: a fresh second
  // factor, or the password again for a first key.
  const [ask, setAsk] = useState<'step_up' | 'password' | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const pending = useRef<(() => Promise<void>) | null>(null)

  const fetchKeys = () => api.get<{ items: SecurityKey[]; keys_off: string }>('/auth/mfa/webauthn/keys')
  const show = (r: { items: SecurityKey[]; keys_off: string }) => {
    setKeys(r.items)
    setOff(r.keys_off || (keysInBrowser() ? '' : 'This browser cannot use security keys.'))
  }
  const load = useCallback(async () => show(await fetchKeys()), [])
  useEffect(() => {
    let alive = true
    fetchKeys().then(
      (r) => alive && show(r),
      (e) => alive && setErr(errorMessage(e)),
    )
    return () => {
      alive = false
    }
  }, [])

  // attempt runs an action; a refusal that names what is missing keeps it to
  // run again once that is given.
  const attempt = async (fn: () => Promise<void>) => {
    setErr('')
    setBusy(true)
    try {
      await fn()
      pending.current = null
      setAsk(null)
      setCode('')
      setPassword('')
    } catch (e) {
      if (e instanceof ApiError && e.code === 'step_up_required') {
        pending.current = fn
        setAsk('step_up')
      } else if (e instanceof ApiError && e.code === 'password_required') {
        pending.current = fn
        setAsk('password')
      } else {
        setErr(keyError(e) ?? errorMessage(e))
      }
    } finally {
      setBusy(false)
    }
  }
  const again = () => (pending.current ? attempt(pending.current) : Promise.resolve())

  const add = (e: FormEvent) => {
    e.preventDefault()
    const n = name.trim()
    void attempt(async () => {
      const credential = await createKey(password || undefined)
      const r = await api.post<{ recovery_codes: string[] | null }>('/auth/mfa/webauthn/register', { name: n, credential })
      setName('')
      if (r.recovery_codes?.length) setCodes(r.recovery_codes)
      await Promise.all([load(), auth.refresh()])
    })
  }
  const rename = (e: FormEvent) => {
    e.preventDefault()
    const r = renaming
    if (!r) return
    void attempt(async () => {
      await api.patch(`/auth/mfa/webauthn/keys/${r.id}`, { name: r.name.trim() })
      setRenaming(null)
      await load()
    })
  }
  const remove = (k: SecurityKey) =>
    void attempt(async () => {
      await api.del(`/auth/mfa/webauthn/keys/${k.id}`)
      await Promise.all([load(), auth.refresh()])
    })
  const newCodes = () =>
    void attempt(async () => {
      const r = await api.post<{ recovery_codes: string[] }>('/auth/mfa/recovery-codes')
      setCodes(r.recovery_codes)
    })
  const proveCode = (e: FormEvent) => {
    e.preventDefault()
    void attempt(async () => {
      await api.post('/auth/mfa/step-up', { code: code.trim() })
      await pending.current?.()
    })
  }

  return (
    <section className="account-keys" aria-labelledby="account-keys-h">
      <h3 id="account-keys-h">Security keys</h3>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {keys === null ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          {keys.length > 0 && (
            <ul className="plain-list key-list">
              {keys.map((k) => (
                <li key={k.id}>
                  {renaming?.id === k.id ? (
                    <form className="key-rename" onSubmit={rename}>
                      <input aria-label="Key name" value={renaming.name} maxLength={64} onChange={(e) => setRenaming({ id: k.id, name: e.target.value })} autoFocus />
                      <button type="submit" className="btn sm primary" disabled={busy || !renaming.name.trim()}>Save</button>
                      <button type="button" className="btn sm" onClick={() => setRenaming(null)}>Cancel</button>
                    </form>
                  ) : (
                    <>
                      <span className="key-name">{k.name}</span>
                      {k.synced && <span className="muted"> · synced</span>}
                      <span className="muted key-when">{k.last_used_at ? `used ${fmtTime(k.last_used_at)}` : `added ${fmtTime(k.created_at)}`}</span>
                      <span className="key-actions">
                        <button type="button" className="link-btn" onClick={() => setRenaming({ id: k.id, name: k.name })}>Rename</button>
                        <button type="button" className="link-btn" disabled={busy} onClick={() => remove(k)}>Remove</button>
                      </span>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
          <form className="key-add" onSubmit={add}>
            <input aria-label="New key's name" placeholder="YubiKey 5C" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} disabled={!!off} />
            <button type="submit" className="btn sm" disabled={busy || !!off || !name.trim()} title={off || undefined}>Add key</button>
          </form>
          {auth.mfaEnrolled && (
            <button type="button" className="link-btn" disabled={busy} onClick={newCodes}>New recovery codes</button>
          )}
        </>
      )}
      {ask === 'step_up' && (
        <form className="key-ask" onSubmit={proveCode}>
          <Field label="Authenticator or recovery code">
            <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
          </Field>
          <div className="actions">
            <button type="submit" className="btn sm primary" disabled={busy || !code.trim()}>Continue</button>
            <KeyButton className="btn sm" onDone={again} onError={setErr} />
          </div>
        </form>
      )}
      {ask === 'password' && (
        <form className="key-ask" onSubmit={(e) => { e.preventDefault(); void again() }}>
          <Field label="Current password">
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          </Field>
          <div className="actions">
            <button type="submit" className="btn sm primary" disabled={busy || !password}>Continue</button>
          </div>
        </form>
      )}
      {codes.length > 0 && (
        <div className="key-codes">
          <p className="muted">Recovery codes. Each works once. Shown only now.</p>
          <div className="recovery-codes">
            {codes.map((c) => <span key={c}>{c}</span>)}
          </div>
          <button type="button" className="btn sm" onClick={() => setCodes([])}>I have saved them</button>
        </div>
      )}
    </section>
  )
}
