// What the terminal and desktop session pages share, so that both say the
// same thing about a session.

import { useNavigate } from 'react-router-dom'
import type { ConnectResponse } from '../../api/types'

/** Access-session ids are 16 random bytes, hex-encoded (store.NewID). The
 *  gateway sends a page its session's id, which then goes into API paths
 *  (file transfer, failover), so only that shape is accepted. */
export const SESSION_ID = /^[0-9a-f]{32}$/

/** The state a terminal or desktop page is opened with: the ticket from the
 *  connect call, and what the page's bar says about the session. */
export interface SessionState {
  ticket: string
  ws_path: string
  target: string
  protocol: string
  asg_id?: string
  asg_instance_id?: string
  instance_label?: string
  switched_from?: string
}

/** switchedState is the state for the session a failover moved to: the new
 *  instance's ticket, under the same target and protocol, naming the
 *  instance it left. */
export function switchedState(from: SessionState, res: ConnectResponse): SessionState {
  return {
    ticket: res.ticket,
    ws_path: res.ws_path,
    target: from.target,
    protocol: from.protocol,
    asg_id: res.asg_id ?? from.asg_id,
    asg_instance_id: res.asg_instance_id,
    instance_label: res.instance_label,
    switched_from: from.instance_label,
  }
}

/** useSwitched is what a session page does once a failover has moved its
 *  session to another instance: open the page at path again on the new
 *  ticket, in place of the session that was lost. */
export function useSwitched(path: '/terminal' | '/desktop', state: SessionState) {
  const nav = useNavigate()
  return (res: ConnectResponse) => {
    nav(path, { replace: true, state: switchedState(state, res) })
  }
}

/** How a session ended: the gateway's reason code, and its own words when it gave any. */
export interface SessionEnd { reason: string; msg?: string }

// The end-of-session dialog's first sentence for each reason the gateway
// reports.
const reasonText: Record<string, string> = {
  user_exit: 'You closed the session.',
  idle_timeout: 'Disconnected after a period without input, as the access policy requires.',
  max_duration: 'The session reached the maximum duration the access policy allows.',
  admin_terminated: 'An administrator ended the session.',
  target_lost: 'The connection to the target was lost.',
  trust_lost: "The target's host key or certificate changed; an administrator must trust it again.",
  error: 'The session ended because of an error.',
}

/** sentence starts the gateway's words with a capital and ends them with a stop. */
function sentence(words: string): string {
  const t = words.trim()
  return t.charAt(0).toUpperCase() + t.slice(1) + (/[.!?]$/.test(t) ? '' : '.')
}

/**
 * endText is what the dialog says about an end: a sentence for the reason,
 * then the gateway's own words when it sent any. For a reason with no
 * sentence here, such as a desktop session the gateway closed, which arrives
 * with its words and no code, those words are the sentence.
 */
export function endText(end: SessionEnd): { lead: string; detail?: string } {
  const known = reasonText[end.reason]
  if (known) return { lead: known, detail: end.msg }
  if (end.msg) return { lead: sentence(end.msg) }
  return { lead: `The session ended: ${end.reason.replace(/_/g, ' ')}.` }
}

// Guacamole statuses the gateway ends a desktop session with: 519 (upstream
// not found) only for a lost target, which may offer another instance of an
// autoscaling group, and 523 (session closed) for an end it decided itself
// (an administrator, a policy limit, a restart), with the reason in words.
const UPSTREAM_NOT_FOUND = 0x0207
const SESSION_CLOSED = 0x020b

/** desktopEnd reads the status a desktop session ended with. Any status but
 *  those two came from guacd or the target, and is an error. */
export function desktopEnd(code: number | undefined, message: string | undefined): SessionEnd {
  const msg = message || undefined
  if (code === UPSTREAM_NOT_FOUND) return { reason: 'target_lost', msg }
  if (code === SESSION_CLOSED) return { reason: 'closed', msg }
  return { reason: 'error', msg }
}

/** saveBlob hands blob to the browser as a download named name, letting go of
 *  its object URL once the browser has had time to start the save. */
export function saveBlob(blob: Blob, name: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000)
}
