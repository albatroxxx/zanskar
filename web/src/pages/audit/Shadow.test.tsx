import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Shadow } from './Shadow'

interface FakeTerm { options: Record<string, unknown>; written: Uint8Array[]; disposed: boolean }
const g = vi.hoisted(() => ({ terms: [] as FakeTerm[], sockets: [] as FakeSocket[], tunnels: [] as string[], clients: [] as FakeClient[], role: 'admin' }))
interface FakeClient { connected: boolean; disconnected: boolean; onstatechange: ((s: number) => void) | null }
interface FakeSocket { url: string; closed: { code?: number; reason?: string } | null; onmessage: ((ev: { data: unknown }) => void) | null; onclose: (() => void) | null; onerror: (() => void) | null }

vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    options: Record<string, unknown>
    written: Uint8Array[] = []
    disposed = false
    constructor(options: Record<string, unknown>) { this.options = options; g.terms.push(this as unknown as FakeTerm) }
    loadAddon() {}
    open() {}
    write(b: Uint8Array) { this.written.push(b) }
    dispose() { this.disposed = true }
  },
}))
vi.mock('@xterm/addon-fit', () => ({ FitAddon: class { fit() {} } }))
// The desktop branch joins the guacd connection read-only; the fake records
// the tunnel's address and whether the client connected and let go.
vi.mock('guacamole-common-js', () => {
  class WebSocketTunnel {
    onerror: (() => void) | null = null
    constructor(url: string) { g.tunnels.push(url) }
  }
  class Client {
    connected = false
    disconnected = false
    onerror: (() => void) | null = null
    onstatechange: ((s: number) => void) | null = null
    constructor() { g.clients.push(this) }
    getDisplay() { return { getElement: () => document.createElement('div') } }
    connect() { this.connected = true }
    disconnect() { this.disconnected = true }
  }
  return { default: { WebSocketTunnel, Client } }
})
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))
// The watcher's portal decides where leaving goes; g.role is who watches.
vi.mock('../../auth/AuthContext', () => ({ useAuth: () => ({ hasRole: (...roles: string[]) => roles.includes(g.role) }) }))

class WS implements FakeSocket {
  url: string
  binaryType = ''
  closed: { code?: number; reason?: string } | null = null
  onmessage: FakeSocket['onmessage'] = null
  onclose: FakeSocket['onclose'] = null
  onerror: FakeSocket['onerror'] = null
  constructor(url: string) { this.url = url; g.sockets.push(this) }
  close(code?: number, reason?: string) { if (!this.closed) { this.closed = { code, reason }; this.onclose?.() } }
}

beforeEach(() => {
  g.terms.length = 0
  g.sockets.length = 0
  g.tunnels.length = 0
  g.clients.length = 0
  g.role = 'admin'
  vi.stubGlobal('WebSocket', WS)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

/** open mounts the watch as a tab of its own does (ADR 0038): with no page
 *  before it to go back to. */
function open(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/audit/shadow/:id" element={<Shadow />} />
        <Route path="/admin/sessions" element={<p>admin sessions list</p>} />
        <Route path="/audit/sessions" element={<p>audit sessions list</p>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('Shadow', () => {
  it('opens a read-only terminal on the session\'s tap, says when it is live, and shows the output', async () => {
    open('/audit/shadow/s1?protocol=ssh&target=web-1')
    expect(await screen.findByText('Watching web-1')).toBeDefined()
    expect(document.title).toBe('Watching web-1 · Zanskar')
    expect(screen.getByText('SSH · read-only')).toBeDefined()
    expect(screen.getByText('this view is audited')).toBeDefined()
    expect(g.sockets[0].url).toBe('ws://localhost:3000/ws/shadow/s1')
    expect(g.terms[0].options.disableStdin).toBe(true)
    expect(screen.getByText('connecting…')).toBeDefined()
    act(() => g.sockets[0].onmessage?.({ data: JSON.stringify({ t: 'ready' }) }))
    expect(screen.getByText(/watching /)).toBeDefined()
    act(() => g.sockets[0].onmessage?.({ data: (() => { const b = new ArrayBuffer(14); new Uint8Array(b).set(new TextEncoder().encode('root@web-1:~# ')); return b })() }))
    expect(new TextDecoder().decode(g.terms[0].written[0])).toBe('root@web-1:~# ')
  })

  it('says when the watched session ends, and when the connection is lost', async () => {
    const { unmount } = open('/audit/shadow/s1?protocol=ssh&target=web-1')
    await screen.findByText('Watching web-1')
    act(() => g.sockets[0].onmessage?.({ data: JSON.stringify({ t: 'end', reason: 'session_ended' }) }))
    expect((await screen.findByRole('dialog', { name: 'Session ended' })).textContent).toContain('The session you were watching has ended.')
    unmount()
    open('/audit/shadow/s2?protocol=winrm&target=win-1')
    await screen.findByText('Watching win-1')
    act(() => g.sockets[1].onerror?.())
    expect((await screen.findByRole('dialog', { name: 'Session ended' })).textContent).toContain('The connection to the gateway was lost.')
  })

  // 2026-11-01: a watch opens in a tab of its own, where going back went
  // nowhere; leaving goes to the sessions list of the watcher's portal.
  it('leaves as a watcher, closing its own socket, for the sessions list of its portal', async () => {
    open('/audit/shadow/s1?protocol=ssh&target=web-1')
    await screen.findByText('Watching web-1')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Stop watching' }))
    expect(g.sockets[0].closed).toEqual({ code: 1000, reason: 'watcher_left' })
    expect(await screen.findByText('admin sessions list')).toBeDefined()
    expect(g.terms[0].disposed).toBe(true)
  })

  it("goes back to an auditor's sessions list once the session has ended", async () => {
    g.role = 'auditor'
    open('/audit/shadow/s1?protocol=ssh&target=web-1')
    await screen.findByText('Watching web-1')
    act(() => g.sockets[0].onmessage?.({ data: JSON.stringify({ t: 'end', reason: 'session_ended' }) }))
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Back to sessions' }))
    expect(await screen.findByText('audit sessions list')).toBeDefined()
  })

  // An application session (ADR 0034) is a browser streamed through guacd:
  // the watcher joins it as a desktop, not as a terminal tap.
  it('watches an application session as a desktop', async () => {
    open('/audit/shadow/s3?protocol=http&target=wiki')
    expect(await screen.findByText('Watching wiki')).toBeDefined()
    expect(screen.getByText('HTTP · read-only')).toBeDefined()
    await vi.waitFor(() => expect(g.clients).toHaveLength(1))
    expect(g.terms).toHaveLength(0)
    expect(g.sockets).toHaveLength(0)
    expect(g.tunnels[0]).toMatch(/^ws:\/\/localhost:3000\/ws\/shadow\/s3\?width=\d+&height=\d+$/)
    expect(g.clients[0].connected).toBe(true)
    act(() => g.clients[0].onstatechange?.(3))
    expect(screen.getByText(/watching /)).toBeDefined()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Stop watching' }))
    expect(g.clients[0].disconnected).toBe(true)
    expect(await screen.findByText('admin sessions list')).toBeDefined()
  })
})
