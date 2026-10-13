import { fmtSeconds, protocolName } from '../../api/format'
import { Modal } from '../../components/ui'
import { endText, type SessionEnd } from './session'

/** SessionEndedDialog tells why a terminal or desktop session ended, in the
 *  same words on both pages, and how long it ran. */
export function SessionEndedDialog({ ended, target, protocol, elapsed, onClose }: { ended: SessionEnd; target: string; protocol: string; elapsed: number; onClose: () => void }) {
  const { lead, detail } = endText(ended)
  return (
    <Modal title="Session ended" onClose={onClose}>
      <p>{lead}</p>
      {detail && <p className="muted">{detail}</p>}
      <p className="muted">
        {target} · {protocolName(protocol)} · ran for {fmtSeconds(elapsed)}. The recording is kept for as long as the retention policy says.
      </p>
      <div className="actions">
        <button className="btn primary" onClick={onClose}>Back to targets</button>
      </div>
    </Modal>
  )
}
