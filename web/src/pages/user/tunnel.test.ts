import { afterEach, describe, expect, it, vi } from 'vitest'
import Guacamole from 'guacamole-common-js'
import type { Status } from 'guacamole-common-js'

/** A WebSocket the test drives by hand, in place of the browser's. */
class FakeSocket {
  static last: FakeSocket | null = null
  url: string
  onopen: ((e: unknown) => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  onclose: ((e: { code: number; reason: string }) => void) | null = null
  onerror: ((e: unknown) => void) | null = null
  sent: string[] = []
  constructor(url: string) {
    this.url = url
    FakeSocket.last = this
  }
  send(d: string) { this.sent.push(d) }
  close() { this.onclose?.({ code: 1000, reason: '' }) }
}

/** The library's tunnel beyond what its type package declares. */
interface LiveTunnel {
  uuid: string | null
  state: number
  connect(data: string): void
  onerror: ((s: Status) => void) | null
  oninstruction: ((opcode: string, args: string[]) => void) | null
}

// Guacamole.Tunnel.State.OPEN and Guacamole.Status.Code.UPSTREAM_TIMEOUT,
// which the type package does not declare.
const OPEN = 1
const UPSTREAM_TIMEOUT = 0x0202

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
    const tunnel = new Guacamole.WebSocketTunnel('ws://gw/ws/desktop?ticket=t') as unknown as LiveTunnel
    const errors: Status[] = []
    tunnel.onerror = (s) => { errors.push(s) }
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
    expect(tunnel.state).toBe(OPEN)

    // Silence after that is still a timeout: the timer is real.
    vi.advanceTimersByTime(16_000)
    expect(errors.map((e) => e.code)).toEqual([UPSTREAM_TIMEOUT])
  })
})
