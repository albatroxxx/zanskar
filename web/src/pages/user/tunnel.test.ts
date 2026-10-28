import { afterEach, describe, expect, it, vi } from 'vitest'
import Guacamole from 'guacamole-common-js'
import type { Status } from 'guacamole-common-js'

/** A WebSocket the test drives by hand, in place of the browser's. */
class FakeSocket {
  static last: FakeSocket | null = null
  onopen: ((e: unknown) => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  onclose: ((e: { code: number; reason: string }) => void) | null = null
  onerror: ((e: unknown) => void) | null = null
  sent: string[] = []
  constructor(public url: string, public protocol?: string) {
    FakeSocket.last = this
  }
  send(d: string) { this.sent.push(d) }
  close() { this.onclose?.({ code: 1000, reason: '' }) }
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

// The gateway sends a nop every few seconds while an application's
// containers start, before the tunnel id. This proves, against the real
// tunnel, that the library's fifteen-second receive timeout is real, that a
// nop before the id resets it, and that the id is still taken afterwards.
describe('the Guacamole tunnel while the gateway starts a session', () => {
  it('stays open on nops before the tunnel id, and times out without them', () => {
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', FakeSocket)
    const tunnel = new Guacamole.WebSocketTunnel('ws://gw/ws/desktop?ticket=t')
    const errors: Status[] = []
    tunnel.onerror = (s) => errors.push(s)
    tunnel.oninstruction = () => {}
    tunnel.connect('')
    const sock = FakeSocket.last
    if (!sock) throw new Error('no socket opened')
    sock.onopen?.({})

    vi.advanceTimersByTime(14_000)
    sock.onmessage?.({ data: '3.nop;' })
    vi.advanceTimersByTime(14_000)
    sock.onmessage?.({ data: '3.nop;' })
    vi.advanceTimersByTime(14_000)
    expect(errors).toEqual([])

    sock.onmessage?.({ data: '0.,3.abc;' })
    expect(tunnel.uuid).toBe('abc')
    expect(tunnel.state).toBe(Guacamole.Tunnel.State.OPEN)

    // Silence after that is still a timeout: the timer is real.
    vi.advanceTimersByTime(16_000)
    expect(errors.map((e) => e.code)).toEqual([Guacamole.Status.Code.UPSTREAM_TIMEOUT])
  })
})
