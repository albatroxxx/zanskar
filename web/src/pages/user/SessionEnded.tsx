import { useNavigate } from 'react-router-dom'
import { fmtSeconds, protocolName } from '../../api/format'
import { Confirm, Modal } from '../../components/ui'
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
export function SessionEndedDialog({ ended, target, protocol, elapsed, again, closable, onClose }: { ended: SessionEnd; target: string; protocol: string; elapsed: number; again?: string; closable?: boolean; onClose: () => void }) {
  const nav = useNavigate()
  const { lead, detail } = endText(ended)
  const href = againHref(again)
  const connectAgain = () => {
    // The record a session link writes: this tab is ours, and the click is
    // the person's own, so the connect page connects without asking.
    recordIntent(href)
    nav(href, { replace: true })
  }
  // A tab one of our links opened has the portal's tab behind it: closing it
  // returns there, where a second Targets list would only be noise (the
  // owner, 2026-11-05). A browser that refuses to close it (a refreshed tab
  // has lost the history that allowed it) leaves it here, and it goes to
  // Targets as before.
  const leave = () => {
    if (!closable) return onClose()
    window.close()
    window.setTimeout(onClose, 200)
  }
  return (
    // Esc and a click outside leave the way the button does: they used to go to
    // Targets in this tab, the second list the button no longer leaves behind
    // (live, 2026-11-05).
    <Modal title="Session ended" onClose={leave}>
      <p>{lead}</p>
      {detail && <p className="muted">{detail}</p>}
      <p className="muted">
        {target} · {protocolName(protocol)} · ran for {fmtSeconds(elapsed)}.
      </p>
      {/* Back to targets is the dialog's main way out, on the right in the
          primary colour, with or without Connect again beside it (the owner,
          2026-11-02). */}
      <div className="actions">
        {href && <button className="btn" onClick={connectAgain}>Connect again</button>}
        <button className="btn primary" onClick={leave}>{closable ? 'Close tab' : 'Back to targets'}</button>
      </div>
    </Modal>
  )
}

/** ConfirmDisconnect asks before the session's own Disconnect ends it, so a
 *  stray click does not (the owner, 2026-11-02); the dialog saying it ended
 *  follows as before. Placed inside the session's page, it shows in full
 *  screen too, and Cancel leaves everything as it was. */
export function ConfirmDisconnect({ target, onConfirm, onClose }: { target: string; onConfirm: () => void; onClose: () => void }) {
  return <Confirm title={`Disconnect from ${target}?`} body="This ends the session." confirmLabel="Disconnect" danger onConfirm={onConfirm} onClose={onClose} />
}
