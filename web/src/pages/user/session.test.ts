import { describe, expect, it } from 'vitest'
import { desktopEnd, endText, switchedState } from './session'

// The terminal and desktop pages both describe an end with endText (B23).
describe('endText', () => {
  it('says each reason the gateway reports in a sentence, with its words after', () => {
    expect(endText({ reason: 'admin_terminated', msg: 'session ended by an administrator' })).toEqual({ lead: 'An administrator ended the session.', detail: 'session ended by an administrator' })
    expect(endText({ reason: 'idle_timeout' }).lead).toBe('Disconnected after a period without input, as the access policy requires.')
    expect(endText({ reason: 'user_exit' }).lead).toBe('You closed the session, or it ended on the target.')
    expect(endText({ reason: 'trust_lost' }).lead).toBe("The target's host key or certificate changed; an administrator must trust it again.")
  })

  it('leads with the gateway words for a reason it has no sentence for', () => {
    expect(endText({ reason: 'policy_revoked', msg: 'your access policy changed' })).toEqual({ lead: 'Your access policy changed.' })
    expect(endText({ reason: 'closed', msg: 'the gateway is restarting; reconnect in a moment.' })).toEqual({ lead: 'The gateway is restarting; reconnect in a moment.' })
  })

  it('names an unknown reason that came without words', () => {
    expect(endText({ reason: 'gateway_restart' })).toEqual({ lead: 'The session ended: gateway restart.' })
  })
})

describe('desktopEnd', () => {
  it('reads 519 as a lost target, 523 as the gateway closing, anything else as an error', () => {
    expect(desktopEnd(0x0207, 'connection to the target was lost')).toEqual({ reason: 'target_lost', msg: 'connection to the target was lost' })
    expect(desktopEnd(0x020b, 'session ended by an administrator')).toEqual({ reason: 'closed', msg: 'session ended by an administrator' })
    expect(desktopEnd(0x0301, 'Authentication failure')).toEqual({ reason: 'error', msg: 'Authentication failure' })
    expect(desktopEnd(undefined, '')).toEqual({ reason: 'error', msg: undefined })
  })
})

// D14: the terminal and desktop pages each built the state for the instance
// a failover moved to. They share switchedState through useSwitched now.
describe('switchedState', () => {
  const lost = { ticket: 'tk1', ws_path: '/ws/terminal', target: 'web', protocol: 'ssh', asg_id: 'g1', asg_instance_id: 'i1', instance_label: 'i-0abc', switched_from: 'i-0old' }

  it('opens the new instance under the same target, naming the instance it left', () => {
    const res = { ticket: 'tk2', expires_at: '2026-10-06T10:01:00Z', ws_path: '/ws/terminal', asg_id: 'g1', asg_instance_id: 'i2', instance_label: 'i-0def' }
    expect(switchedState(lost, res)).toEqual({
      ticket: 'tk2', ws_path: '/ws/terminal', target: 'web', protocol: 'ssh', asg_id: 'g1', asg_instance_id: 'i2', instance_label: 'i-0def', switched_from: 'i-0abc',
    })
  })

  it('keeps the group when the answer does not name it', () => {
    expect(switchedState(lost, { ticket: 'tk2', expires_at: '', ws_path: '/ws/terminal' }).asg_id).toBe('g1')
  })
})
