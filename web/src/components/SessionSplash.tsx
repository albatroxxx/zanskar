import { useLocation } from 'react-router-dom'
import { protocolName } from '../api/format'
import { useTitle } from './title'

/**
 * SessionSplash is what a session's tab shows until the session page has
 * something to show: the session page's dark ground and one line. The tab
 * goes from the click to the session without a page of another kind on the
 * way (the live console, 2026-11-01: a portal page with a Connect button,
 * then a light "Loading desktop", flashed by before the application drew).
 */
export function SessionSplash({ text }: { text: string }) {
  return (
    <div className="session-splash" role="status">
      {text}
    </div>
  )
}

/** SessionLoading is the session pages' fallback while their code loads:
 *  the splash, naming the target the connect page handed over, and the tab
 *  already titled as the session page will title it, so the title does not
 *  blink to "Zanskar" on the way. */
export function SessionLoading() {
  const s = useLocation().state as { target?: string; protocol?: string } | null
  const target = s?.target
  useTitle(target && s?.protocol ? `${target} · ${protocolName(s.protocol)}` : undefined)
  return <SessionSplash text={target ? `Connecting to ${target}…` : 'Connecting…'} />
}
