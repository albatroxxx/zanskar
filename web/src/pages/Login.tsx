import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import QRCode from 'qrcode'
import { useAuth } from '../auth/AuthContext'
import { api, ApiError, errorMessage, signInEnded } from '../api/client'
import { Alert, Field } from '../components/ui'
import { RetryIcon, SignInIcon } from '../components/icons'
import { safeReturnPath, signInError } from './loginErrors'

type Step = 'password' | 'change' | 'verify' | 'enroll' | 'recovery'

type Provider = { id: string; name: string; type: string; not_answering?: boolean }

const listProviders = () => api.get<{ items: Provider[] }>('/auth/providers').then((r) => r.items ?? [])

export function Login() {
  const auth = useAuth()
  const loc = useLocation()
  // Where to go once signed in: what the guard remembered, else the ?next=
  // the gateway's single sign-on sends while a code is still owed (B20);
  // either way only a path on this site. With no destination at all, /home
  // resolves to the portal the account signs in to (ADR 0029) — the roles are
  // not known until the sign-in answers, so the choice cannot be made here.
  const stated = (loc.state as { from?: unknown } | null)?.from ?? new URLSearchParams(loc.search).get('next')
  const from = stated == null ? '/home' : safeReturnPath(stated)
  const [step, setStep] = useState<Step>('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [err, setErr] = useState(() => signInError(new URLSearchParams(window.location.search).get('error')))
  const [busy, setBusy] = useState(false)
  const [enroll, setEnroll] = useState<{ secret: string; otpauth_url: string; qr: string } | null>(null)
  const [providers, setProviders] = useState<Provider[]>([])
  // A provider the gateway cannot reach has its button greyed out and the
  // reason in a tip, shown on hover, focus or a tap and closed with Esc; a
  // check beside it reads the list again (2026-11-11, owner). The tip open
  // is that provider's id.
  const [tip, setTip] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)
  const checkingNow = useRef(false)
  const [said, setSaid] = useState('')
  // The provider whose button takes focus once it answers again, so the
  // check that disappears with it does not leave focus nowhere.
  const focusOnUp = useRef<string | null>(null)
  // The system-use notification an admin configured, shown before any
  // credential is entered. Read without a session; empty means none.
  const [banner, setBanner] = useState('')
  const [recovery, setRecovery] = useState<string[]>([])
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')

  // Single sign-on providers get a button each; LDAP signs in through the form.
  const sso = providers.filter((p) => p.type === 'oidc')
  // A partial session that survived a reload lands on the right step.
  const effectiveStep: Step = step === 'password' && auth.status === 'partial' ? (auth.pending === 'enroll' ? 'enroll' : auth.pending === 'password' ? 'change' : 'verify') : step

  useEffect(() => {
    listProviders()
      .then(setProviders)
      .catch(() => {})
    api.get<{ text: string }>('/system/banner')
      .then((b) => setBanner(b.text ?? ''))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!tip) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setTip(null)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [tip])

  useEffect(() => {
    if (effectiveStep === 'enroll' && !enroll) {
      auth
        .enrollTotp()
        .then(async (e) => setEnroll({ ...e, qr: await QRCode.toDataURL(e.otpauth_url, { margin: 1, width: 192 }) }))
        .catch((e) => setErr(errorMessage(e)))
    }
  }, [effectiveStep, enroll, auth])

  if (auth.status === 'full' && effectiveStep !== 'recovery') return <Navigate to={from} replace />

  // The list says what the gateway last found asking each provider, every
  // 20 seconds for one that is failing (health.go); reading it never makes
  // the gateway call out.
  const checkAgain = async (p: Provider) => {
    if (checkingNow.current) return
    checkingNow.current = true
    setChecking(true)
    setSaid('')
    try {
      const items = await listProviders()
      const now = items.find((x) => x.id === p.id)
      if (now && !now.not_answering) {
        focusOnUp.current = p.id
        setTip(null)
        setSaid(`${p.name} is answering again.`)
        // The note a failed sign-in brought back is no longer so.
        if (!items.some((x) => x.not_answering)) setErr((e) => (e === signInError('provider_unavailable') ? '' : e))
      } else if (now) {
        setTip(p.id)
        setSaid(`${p.name} is still not answering.`)
      }
      setProviders(items)
    } catch {
      setSaid('Could not check. Try again.')
    } finally {
      checkingNow.current = false
      setChecking(false)
    }
  }

  const submitPassword = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const res = await auth.login(username.trim(), password)
      if (res.status === 'password_change_required') {
        // Keep the password typed: it is the "current" one the change asks for.
        setStep('change')
        return
      }
      setPassword('')
      if (res.status === 'mfa_required') setStep('verify')
      else if (res.status === 'mfa_enrollment_required') setStep('enroll')
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const submitChange = async (e: FormEvent) => {
    e.preventDefault()
    if (newPw !== confirmPw) {
      setErr('The new passwords do not match.')
      return
    }
    setBusy(true)
    setErr('')
    try {
      const res = await auth.changePassword(password, newPw)
      setPassword('')
      setNewPw('')
      setConfirmPw('')
      if (res.status === 'mfa_required') setStep('verify')
      else if (res.status === 'mfa_enrollment_required') setStep('enroll')
      else setStep('password')
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  // A wrong code stays on the code step. A sign-in that has ended (#205)
  // goes back to the password, saying why.
  const afterCodeError = (e: unknown) => {
    setCode('')
    if (signInEnded(e)) {
      setStep('password')
      setEnroll(null)
      setErr(e instanceof ApiError && e.code === 'sign_in_ended' ? 'Too many wrong codes. Sign in again.' : 'Your sign-in expired. Sign in again.')
      return
    }
    setErr(errorMessage(e))
  }

  const submitVerify = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await auth.verifyTotp(code.trim())
      // What is owed next is the gateway's to say (/auth/me): a password
      // change an administrator asked for, or nothing. Leaving the local
      // step at verify kept the code form on screen after a right code
      // (2026-11-09; ADR 0047).
      setStep('password')
    } catch (e) {
      afterCodeError(e)
    } finally {
      setBusy(false)
    }
  }

  const submitConfirm = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const codes = await auth.confirmTotp(code.trim())
      setRecovery(codes)
      setStep('recovery')
    } catch (e) {
      afterCodeError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login">
        <div className="brand">
          <img src="/logo-mark.svg" alt="" />
          <h1>ZANSKAR</h1>
          <span>agentless access gateway</span>
        </div>
        {banner && (
          <div className="login-banner" role="note" aria-label="System use notification">{banner}</div>
        )}
        <div className="card">
          {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}

          {effectiveStep === 'password' && (
            <form onSubmit={submitPassword}>
              <Field label="Username">
                <input id="username" autoFocus autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setUsername(e.target.value)} required />
              </Field>
              <Field label="Password">
                <input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </Field>
              <button type="submit" className="btn primary" disabled={busy} style={{ width: '100%', justifyContent: 'center' }}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
              {sso.length > 0 && (
                <div className="sso">
                  <div className="sso-divider" role="separator" aria-label="or"><span aria-hidden="true">or</span></div>
                  {sso.map((p) =>
                    p.not_answering ? (
                      // The gateway could not reach the provider: said before
                      // anyone presses and waits (2026-11-03, idea 1). The
                      // button stays focusable so the reason can be reached.
                      <div className="sso-row" key={p.id}>
                        <span className="sso-wrap" onPointerEnter={(e) => e.pointerType === 'mouse' && setTip(p.id)} onPointerLeave={(e) => e.pointerType === 'mouse' && setTip(null)}>
                          <button type="button" id={`sso-${p.id}`} className="btn sso-btn is-down" aria-disabled="true" aria-describedby={`sso-down-${p.id}`} onFocus={() => setTip(p.id)} onBlur={() => setTip(null)} onClick={() => setTip(p.id)}>
                            <SignInIcon />
                            <span>Continue with {p.name}</span>
                          </button>
                          <span role="tooltip" id={`sso-down-${p.id}`} className={'sso-tip' + (tip === p.id ? ' open' : '')}>
                            {p.name} is not answering right now. A password account still works.
                          </span>
                        </span>
                        <button type="button" className="btn sso-retry" aria-label={`Check ${p.name} again`} title="Check again" aria-busy={checking} onBlur={() => setTip(null)} onClick={() => void checkAgain(p)}>
                          <RetryIcon />
                        </button>
                      </div>
                    ) : (
                      <a
                        key={p.id}
                        id={`sso-${p.id}`}
                        className="btn sso-btn"
                        href={`/api/v1/auth/oidc/${p.id}/start?next=${encodeURIComponent(from)}`}
                        ref={(el) => {
                          if (el && focusOnUp.current === p.id) {
                            focusOnUp.current = null
                            el.focus()
                          }
                        }}
                      >
                        <SignInIcon />
                        <span>Continue with {p.name}</span>
                      </a>
                    ),
                  )}
                  <p className="sr-only" role="status">{said}</p>
                </div>
              )}
            </form>
          )}

          {effectiveStep === 'change' && (
            <form onSubmit={submitChange}>
              <p className="muted" style={{ marginTop: 0 }}>Choose your own password to continue.</p>
              {!password && (
                <Field label="Current password">
                  <input id="current-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                </Field>
              )}
              <Field label="New password" hint="At least 12 characters">
                <input id="new-password" type="password" autoFocus autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} required minLength={12} />
              </Field>
              <Field label="New password again">
                <input id="new-password-2" type="password" autoComplete="new-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} required />
              </Field>
              <div className="actions" style={{ justifyContent: 'space-between' }}>
                <button type="button" className="btn ghost" onClick={() => void auth.logout().then(() => setStep('password'))}>Cancel</button>
                <button type="submit" className="btn primary" disabled={busy}>Set password and continue</button>
              </div>
            </form>
          )}

          {effectiveStep === 'verify' && (
            <form onSubmit={submitVerify}>
              <p className="muted" style={{ marginTop: 0 }}>Enter the six-digit code from your authenticator, or a recovery code.</p>
              <Field label="Code">
                <input id="totp" autoFocus inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} required />
              </Field>
              <div className="actions" style={{ justifyContent: 'space-between' }}>
                <button type="button" className="btn ghost" onClick={() => void auth.logout().then(() => setStep('password'))}>Cancel</button>
                <button type="submit" className="btn primary" disabled={busy}>Verify</button>
              </div>
            </form>
          )}

          {effectiveStep === 'enroll' && (
            <form onSubmit={submitConfirm}>
              <p className="muted" style={{ marginTop: 0 }}>Scan with your authenticator app, then enter its code.</p>
              {enroll ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                  <img className="qr" src={enroll.qr} alt="TOTP enrollment QR code" width={192} height={192} />
                  <div style={{ textAlign: 'center', maxWidth: '100%' }}>
                    <div className="muted" style={{ fontSize: '0.8rem' }}>Manual entry key</div>
                    <code style={{ wordBreak: 'break-all' }}>{enroll.secret}</code>
                  </div>
                </div>
              ) : (
                <div className="muted">Preparing enrollment…</div>
              )}
              <Field label="Code from the app">
                <input id="totp-confirm" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} required />
              </Field>
              <div className="actions" style={{ justifyContent: 'space-between' }}>
                <button type="button" className="btn ghost" onClick={() => void auth.logout().then(() => setStep('password'))}>Cancel</button>
                <button type="submit" className="btn primary" disabled={busy || !enroll}>Activate</button>
              </div>
            </form>
          )}

          {effectiveStep === 'recovery' && (
            <div>
              <h2>Save your recovery codes</h2>
              <p className="muted">Each works once. Shown only now.</p>
              <div className="recovery-codes">
                {recovery.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
              <div className="actions" style={{ justifyContent: 'flex-end', marginTop: 16 }}>
                {/* Leaving this step hands over to the redirect at the top: where the
                    user was going, now that they are fully signed in, or the next
                    step still owed. It used to load from as a new page, which sent a
                    ?next= the page was handed into location.href. */}
                <button className="btn primary" onClick={() => setStep('password')}>I have saved them</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
