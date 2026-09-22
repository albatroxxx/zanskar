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
    setLeaving(true)
    // Ask the server what the session is actually worth before leaving.
    // Without this the context still reports a full session and the login page
    // would send the user straight back to the page that just failed.
    await auth.refresh()
    setEnded(false)
    nav('/login', { state: { from: loc.pathname + loc.search }, replace: true })
  }

  return (
    <Modal title="Session expired" onClose={() => void signIn()}>
      <p>
        You have been signed out, either after a period of inactivity or because the session was
        ended somewhere else.
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
