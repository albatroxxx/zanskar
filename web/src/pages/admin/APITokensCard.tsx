import { useEffect, useState, type FormEvent } from 'react'
import { ApiError, api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import { Alert, Confirm, Field, Loading, StateBadge } from '../../components/ui'
import { CopyButton } from '../../components/CopyButton'

/** An API token as listed (ADR 0044); never its secret. */
export interface APIToken {
  id: string
  user_id: string
  username?: string
  name: string
  prefix: string
  created_at: string
  expires_at: string
  last_used_at?: string
  revoked_at?: string
  /** What holds now: active, expired or revoked (ADR 0047). */
  state: 'active' | 'expired' | 'revoked'
}

const lives = [
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 365, label: '1 year' },
]

/**
 * APITokensCard, in Settings, makes the tokens automation signs in with
 * (2026-11-03, idea 10; ADR 0044): the Terraform provider, a pipeline
 * importing the configuration file. A token is the administrator who made
 * it, on the configuration API only, with no second factor; making one asks
 * for a recent code, and its secret is shown once.
 */
export function APITokensCard() {
  const [tokens, setTokens] = useState<APIToken[] | null>(null)
  const [loadErr, setLoadErr] = useState('')
  const [name, setName] = useState('')
  const [days, setDays] = useState(90)
  const [needCode, setNeedCode] = useState(false)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [made, setMade] = useState<{ name: string; secret: string } | null>(null)
  const [revoking, setRevoking] = useState<APIToken | null>(null)

  const load = () =>
    api
      .get<{ items: APIToken[] }>('/admin/api-tokens')
      .then((p) => {
        setTokens(p.items ?? [])
        setLoadErr('')
      })
      .catch((e) => setLoadErr(errorMessage(e)))
  useEffect(() => {
    void load()
  }, [])

  const make = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      if (needCode) await api.post('/auth/mfa/step-up', { code: code.trim() })
      const t = await api.post<APIToken & { secret: string }>('/admin/api-tokens', { name: name.trim(), days })
      setMade({ name: t.name, secret: t.secret })
      setName('')
      setNeedCode(false)
      setCode('')
      void load()
    } catch (e2) {
      if (e2 instanceof ApiError && e2.code === 'step_up_required') setNeedCode(true)
      else setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card" id="settings-api-tokens">
      <h2>API tokens</h2>
      <p className="muted">Acts as you, without a second factor.</p>
      {made && (
        <Alert tone="ok" onDismiss={() => setMade(null)}>
          <div>Token “{made.name}” made. Copy it now; it is not shown again.</div>
          <div className="token-secret">
            <code className="mono">{made.secret}</code> <CopyButton text={made.secret} name="the token" />
          </div>
        </Alert>
      )}
      {loadErr ? (
        <Alert tone="danger">The tokens could not be loaded: {loadErr}</Alert>
      ) : tokens === null ? (
        <Loading />
      ) : tokens.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Owner</th>
                <th>Token</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>State</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => {
                return (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td>{t.username || t.user_id}</td>
                    <td className="mono">{t.prefix}…</td>
                    <td className="muted">{fmtTime(t.expires_at)}</td>
                    <td className="muted">{t.last_used_at ? fmtTime(t.last_used_at) : 'never'}</td>
                    <td><StateBadge lifecycle="api_token" state={t.state} /></td>
                    <td>{t.state === 'active' && <button className="btn sm" onClick={() => setRevoking(t)}>Revoke…</button>}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">No tokens yet.</p>
      )}
      <form className="actions" onSubmit={(e) => void make(e)}>
        <input className="filter-control" aria-label="Token name" placeholder="what it is for, e.g. terraform-prod" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        <select className="filter-control" aria-label="Lifetime" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {lives.map((l) => <option key={l.days} value={l.days}>{l.label}</option>)}
        </select>
        <button type="submit" className="btn primary sm" disabled={busy || !name.trim() || (needCode && !code.trim())}>{busy ? 'Making…' : 'Make token'}</button>
      </form>
      {needCode && (
        <Field label="Authenticator code">
          <input id="token-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
        </Field>
      )}
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {revoking && (
        <Confirm
          title={`Revoke “${revoking.name}”?`}
          body="Anything using it stops at once."
          confirmLabel="Revoke"
          danger
          onClose={() => setRevoking(null)}
          onConfirm={async () => {
            await api.del(`/admin/api-tokens/${revoking.id}`)
            void load()
          }}
        />
      )}
    </div>
  )
}
