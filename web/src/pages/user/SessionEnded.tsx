import { useNavigate } from 'react-router-dom'
import { fmtSeconds, protocolName } from '../../api/format'
import { Modal } from '../../components/ui'
import { connectHref, parseIntent, recordIntent } from './intent'
import { endText, type SessionEnd } from './session'

/** againHref is the connect page an ended session can go back to, or ''.
 *  Rebuilt from what it parses to, so only a connect page of the shape
 *  ConnectPage reads is ever offered. */
function againHref(again?: string): string {
  if (!again?.startsWith('/connect?')) return ''
  const intent = parseIntent(new URLSearchParams(again.slice('/connect?'.length)))
  return intent ? connectHref(intent) : ''
}

/** SessionEndedDialog tells why a terminal or desktop session ended, in the
 *  same words on both pages, and how long it ran. A session runs in a tab of
 *  its own (ADR 0038), so the tab offers to connect again rather than only a
 *  second targets list (the live console, 2026-11-01): that goes through
 *  the connect page, which asks for a credential again where one is needed. */
export function SessionEndedDialog({ ended, target, protocol, elapsed, again, onClose }: { ended: SessionEnd; target: string; protocol: string; elapsed: number; again?: string; onClose: () => void }) {
  const nav = useNavigate()
  const { lead, detail } = endText(ended)
  const href = againHref(again)
  const connectAgain = () => {
    // The record a session link writes: this tab is ours, and the click is
    // the person's own, so the connect page connects without asking.
    recordIntent(href)
    nav(href, { replace: true })
  }
  return (
    <Modal title="Session ended" onClose={onClose}>
      <p>{lead}</p>
      {detail && <p className="muted">{detail}</p>}
      <p className="muted">
        {target} · {protocolName(protocol)} · ran for {fmtSeconds(elapsed)}.
      </p>
      <div className="actions">
        <button className={'btn' + (href ? '' : ' primary')} onClick={onClose}>Back to targets</button>
        {href && <button className="btn primary" onClick={connectAgain}>Connect again</button>}
      </div>
    </Modal>
  )
}
