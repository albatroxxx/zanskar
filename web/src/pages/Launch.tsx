import { useEffect, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Alert } from '../components/ui'

/** What each refusal code from the gateway means, in words. */
const reasons: Record<string, string> = {
  approval_required: 'needs an approved request before you can open it; ask for one under Targets',
  policy_denied: 'is not granted to you by any policy',
  mfa_required_by_policy: 'needs an enrolled authenticator; enroll one first',
  not_found: 'is not served by this gateway',
  target_disabled: 'is disabled',
  apps_not_ready: 'cannot be served: applications are not configured on this gateway',
  restarting: 'cannot be opened while the gateway restarts; try again in a minute',
}

const follow = (a: HTMLAnchorElement) => a.click()

/**
 * Launch is where an application host sends a browser that has no session on
 * it (ADR 0033): the host set a state cookie and came here with the
 * application's label, the state and the path to return to. Signed in (the
 * route guard saw to that), the page follows one link to the gateway's own
 * route, which sends the browser on to the application, or back here with
 * the reason it was refused, which the application host itself cannot say.
 * A link rather than a form: the console's content security policy keeps
 * form submissions to its own origin, and the gateway's answer is a redirect
 * to the application's. No script decides where the browser goes.
 */
export function Launch({ go = follow }: { go?: (link: HTMLAnchorElement) => void }) {
  const q = new URLSearchParams(useLocation().search)
  const app = q.get('app') ?? ''
  const state = q.get('state') ?? ''
  const next = q.get('next') ?? '/'
  const error = q.get('error') ?? ''
  const link = useRef<HTMLAnchorElement>(null)
  // Once: the page re-renders as the sign-in state settles.
  const followed = useRef(false)

  useEffect(() => {
    if (followed.current || !app || !state || error || !link.current) return
    followed.current = true
    go(link.current)
  }, [app, state, error, go])

  if (error) {
    const what = app || 'The application'
    return (
      <div className="empty" style={{ maxWidth: 520, margin: '48px auto' }}>
        <Alert tone={error === 'approval_required' ? 'warn' : 'danger'}>{what} {reasons[error] ?? 'could not be opened'}.</Alert>
        <p>
          <Link className="btn" to="/">Back to the access portal</Link>
        </p>
      </div>
    )
  }
  if (!app || !state) {
    return (
      <div className="empty">
        <p>Open an application from the <Link to="/">access portal</Link>; this page is where its address sends you to sign in.</p>
      </div>
    )
  }
  const href = '/api/v1/me/applications/launch?' + new URLSearchParams({ app, state, next }).toString()
  return (
    <div className="empty">
      <p>Opening {app}…</p>
      <p>
        <a ref={link} className="btn primary" href={href}>Open {app}</a>
      </p>
    </div>
  )
}
