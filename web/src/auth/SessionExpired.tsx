import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { setSessionEndedHandler } from '../api/client'
import { Modal } from '../components/ui'
import { useAuth } from './AuthContext'

/**
 * SessionExpired turns an expired session into one clear interruption instead
 * of a bare "sign in required" error inside whichever page happened to be
 * loading.
 *
 * The page stays visible behind the dialog so the user can still see where
 * they were, and every way out of the dialog leads to sign-in: dismissing it
 * back onto a page whose data will never load again would be a dead end.
 */

/**
 * How long "Go to sign in" waits for the gateway to say what the session is
 * worth. It waited for ever (until 1.11.1): a check that did not come back,
 * as after the computer slept, left "Taking you to sign in…" on screen.
 */
const confirmWait = 5000

/** within is true when p settles inside ms, false when it does not. */
function within(p: Promise<unknown>, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(false), ms)
    const done = () => {
      clearTimeout(t)
      resolve(true)
    }
    p.then(done, done)
  })
}

export function SessionExpired() {
  const [ended, setEnded] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const auth = useAuth()
  const nav = useNavigate()
  const loc = useLocation()

  useEffect(() => {
    setSessionEndedHandler(() => setEnded(true))
    return () => setSessionEndedHandler(null)
  }, [])

  // The login page reports its own failures, and it is where this dialog sends
  // people anyway, so there is nothing to interrupt once they are there.
  if (!ended || loc.pathname === '/login') return null

  const signIn = async () => {
    // A click outside the dialog while it waits is the same request again.
    if (leaving) return
    setLeaving(true)
    // Ask the server what the session is actually worth before leaving.
    // Without this the context still reports a full session and the login page
    // would send the user straight back to the page that just failed. If the
    // server does not answer, believe the 401 that opened the dialog.
    if (!(await within(auth.refresh(), confirmWait))) auth.forget()
    // The dialog can open again later (a page left open signs out again);
    // until 1.11.1 it came back with "Taking you to sign in…", disabled.
    setLeaving(false)
    setEnded(false)
    nav('/login', { state: { from: loc.pathname + loc.search }, replace: true })
  }

  return (
    <Modal title="Session expired" onClose={() => void signIn()}>
      <p>
        You have been signed out.
      </p>
      <p className="muted">Signing in again brings you back to this page.</p>
      <div className="actions">
        <button className="btn primary" autoFocus disabled={leaving} onClick={() => void signIn()}>
          {leaving ? 'Taking you to sign in…' : 'Go to sign in'}
        </button>
      </div>
    </Modal>
  )
}
