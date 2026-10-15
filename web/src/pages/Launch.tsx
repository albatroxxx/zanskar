import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { api, ApiError, errorMessage } from '../api/client'
import { Alert } from '../components/ui'

/** go sends the browser to the application; a prop so tests can watch it. */
const leave = (url: string) => window.location.replace(url)

/**
 * Launch is where an application host sends a browser that has no session
 * on it (ADR 0033): the host set a state cookie and came here with the
 * application's label, the state and the path to return to. Signed in (the
 * route guard saw to that), the page asks the API for the hand-off and sends
 * the browser straight back; a refusal is explained in place, since the
 * application host itself cannot say why.
 */
export function Launch({ go = leave }: { go?: (url: string) => void }) {
  const q = new URLSearchParams(useLocation().search)
  const app = q.get('app') ?? ''
  const state = q.get('state') ?? ''
  const next = q.get('next') ?? '/'
  const [err, setErr] = useState<{ code: string; message: string } | null>(null)

  useEffect(() => {
    if (!app || !state) return
    let cancelled = false
    api
      .post<{ url: string }>('/me/applications/launch', { app, state, next })
      .then((r) => {
        if (!cancelled) go(r.url)
      })
      .catch((e) => {
        if (!cancelled) setErr({ code: e instanceof ApiError ? e.code : '', message: errorMessage(e) })
      })
    return () => {
      cancelled = true
    }
  }, [app, state, next, go])

  if (!app || !state) {
    return (
      <div className="empty">
        <p>Open an application from the <Link to="/">access portal</Link>; this page is where its address sends you to sign in.</p>
      </div>
    )
  }
  if (!err) return <div className="empty">Opening {app}…</div>
  return (
    <div className="empty" style={{ maxWidth: 520, margin: '48px auto' }}>
      <Alert tone={err.code === 'approval_required' ? 'warn' : 'danger'}>
        {err.code === 'approval_required'
          ? `${app} needs an approved request before you can open it.`
          : err.code === 'policy_denied'
            ? `You do not have access to ${app}: ${err.message}.`
            : `${app} could not be opened: ${err.message}`}
      </Alert>
      <p>
        <Link className="btn" to="/">Back to the access portal</Link>
      </p>
    </div>
  )
}
