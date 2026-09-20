import { useEffect, useState, type FormEvent } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import QRCode from 'qrcode'
import { useAuth } from '../auth/AuthContext'
import { errorMessage } from '../api/client'
import { Alert, Field } from '../components/ui'

type Step = 'password' | 'verify' | 'enroll' | 'recovery'

export function Login() {
  const auth = useAuth()
  const loc = useLocation()
  const from = (loc.state as { from?: string } | null)?.from ?? '/'
  const [step, setStep] = useState<Step>('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [enroll, setEnroll] = useState<{ secret: string; otpauth_url: string; qr: string } | null>(null)
  const [recovery, setRecovery] = useState<string[]>([])

  // A partial session that survived a reload lands on the right step.
  const effectiveStep: Step = step === 'password' && auth.status === 'partial' ? (auth.pending === 'enroll' ? 'enroll' : 'verify') : step

  useEffect(() => {
    if (effectiveStep === 'enroll' && !enroll) {
      auth
        .enrollTotp()
        .then(async (e) => setEnroll({ ...e, qr: await QRCode.toDataURL(e.otpauth_url, { margin: 1, width: 192 }) }))
        .catch((e) => setErr(errorMessage(e)))
    }
  }, [effectiveStep, enroll, auth])

  if (auth.status === 'full' && effectiveStep !== 'recovery') return <Navigate to={from} replace />

  const submitPassword = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const res = await auth.login(username.trim(), password)
      setPassword('')
      if (res.status === 'mfa_required') setStep('verify')
      else if (res.status === 'mfa_enrollment_required') setStep('enroll')
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const submitVerify = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await auth.verifyTotp(code.trim())
    } catch (e) {
      setErr(errorMessage(e))
      setCode('')
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
      setErr(errorMessage(e))
      setCode('')
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
        <div className="card">
          {err && <Alert tone="danger">{err}</Alert>}

          {effectiveStep === 'password' && (
            <form onSubmit={submitPassword}>
              <Field label="Username">
                <input id="username" autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
              </Field>
              <Field label="Password">
                <input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </Field>
              <button className="btn primary" disabled={busy} style={{ width: '100%', justifyContent: 'center' }}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
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
                <button className="btn primary" disabled={busy}>Verify</button>
              </div>
            </form>
          )}

          {effectiveStep === 'enroll' && (
            <form onSubmit={submitConfirm}>
              <p className="muted" style={{ marginTop: 0 }}>This deployment requires a second factor. Scan the code with your authenticator app, then enter the six-digit code it shows.</p>
              {enroll ? (
                <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}>
                  <img src={enroll.qr} alt="TOTP enrollment QR code" width={192} height={192} style={{ borderRadius: 6, background: '#fff' }} />
                  <div style={{ flex: 1, minWidth: 180 }}>
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
                <button className="btn primary" disabled={busy || !enroll}>Activate</button>
              </div>
            </form>
          )}

          {effectiveStep === 'recovery' && (
            <div>
              <h2>Save your recovery codes</h2>
              <p className="muted">Each code works once if you lose your authenticator. They will not be shown again.</p>
              <div className="recovery-codes">
                {recovery.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
              <div className="actions" style={{ justifyContent: 'flex-end', marginTop: 16 }}>
                <button className="btn primary" onClick={() => (window.location.href = from)}>I have saved them</button>
              </div>
            </div>
          )}
        </div>
        <div className="foot">Sign-in attempts are recorded.</div>
      </div>
    </div>
  )
}
