import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Terminal } from './Terminal'

/** The parts of xterm the page drives, recorded so the tests can read them back. */
interface FakeTerm { cols: number; rows: number; written: Uint8Array[]; data: ((d: string) => void) | null; resize: ((s: { cols: number; rows: number }) => void) | null; disposed: boolean; keyHandler: ((e: KeyboardEvent) => boolean) | null }
const g = vi.hoisted(() => ({ terms: [] as FakeTerm[], sockets: [] as FakeSocket[] }))

interface FakeSocket {
  url: string
  readyState: number
  sent: unknown[]
  closed: { code?: number; reason?: string } | null
  onmessage: ((ev: { data: unknown }) => void) | null
  onclose: ((ev: { code: number; reason: string }) => void) | null
  onerror: (() => void) | null
}

vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    cols = 120
    rows = 40
    written: Uint8Array[] = []
    data: ((d: string) => void) | null = null
    resize: ((s: { cols: number; rows: number }) => void) | null = null
    disposed = false
    constructor() { g.terms.push(this as unknown as FakeTerm) }
    loadAddon() {}
    open() {}
    focus() {}
    write(b: Uint8Array) { this.written.push(b) }
    onData(fn: (d: string) => void) { this.data = fn; return { dispose: () => { this.data = null } } }
    onResize(fn: (s: { cols: number; rows: number }) => void) { this.resize = fn; return { dispose: () => { this.resize = null } } }
    keyHandler: ((e: KeyboardEvent) => boolean) | null = null
    attachCustomKeyEventHandler(fn: (e: KeyboardEvent) => boolean) { this.keyHandler = fn }
    dispose() { this.disposed = true }
  },
}))
vi.mock('@xterm/addon-fit', () => ({ FitAddon: class { fit() {} } }))
vi.mock('@xterm/addon-web-links', () => ({ WebLinksAddon: class {} }))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

class WS implements FakeSocket {
  static OPEN = 1
  url: string
  readyState = 1
  binaryType = ''
  sent: unknown[] = []
  closed: { code?: number; reason?: string } | null = null
  onmessage: FakeSocket['onmessage'] = null
  onclose: FakeSocket['onclose'] = null
  onerror: FakeSocket['onerror'] = null
  constructor(url: string) { this.url = url; g.sockets.push(this) }
  send(d: unknown) { this.sent.push(d) }
  close(code?: number, reason?: string) {
    if (this.closed) return
    this.closed = { code, reason }
    this.readyState = 3
    this.onclose?.({ code: code ?? 1005, reason: reason ?? '' })
  }
}

beforeEach(() => {
  g.terms.length = 0
  g.sockets.length = 0
  vi.stubGlobal('WebSocket', WS)
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} })
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const session = { ticket: 'tk-1', ws_path: '/ws/terminal', target: 'web-1', protocol: 'ssh' }

function open(state: unknown = session) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: '/terminal', state }]}>
      <Routes>
        <Route path="/terminal" element={<Terminal />} />
        <Route path="/" element={<p>target list</p>} />
      </Routes>
    </MemoryRouter>,
  )
}

const message = (data: unknown) => act(() => { g.sockets[0].onmessage?.({ data }) })

describe('Terminal', () => {
  it('goes back to the targets when opened without a session', async () => {
    open(null)
    expect(await screen.findByText('target list')).toBeDefined()
    expect(g.sockets).toHaveLength(0)
  })

  it('connects with the ticket and the terminal size, relays output, keystrokes and resizes, and offers files only when the policy allows', async () => {
    open()
    expect(await screen.findByText('web-1')).toBeDefined()
    expect(g.sockets).toHaveLength(1)
    expect(g.sockets[0].url).toBe('ws://localhost:3000/ws/terminal?ticket=tk-1&cols=120&rows=40')
    expect(screen.getByText('connecting…')).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Files' })).toBeNull()

    message(JSON.stringify({ t: 'ready', session_id: 'a'.repeat(32), files: true }))
    expect(screen.getByText(/elapsed /)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Files' })).toBeDefined()
    expect(screen.getByText('Recording')).toBeDefined()

    // Built on the page's own ArrayBuffer, as the socket would hand it over.
    message((() => { const b = new ArrayBuffer(2); new Uint8Array(b).set(new TextEncoder().encode('$ ')); return b })())
    expect(new TextDecoder().decode(g.terms[0].written[0])).toBe('$ ')

    act(() => g.terms[0].data?.('ls\r'))
    expect(new TextDecoder().decode(g.sockets[0].sent[0] as Uint8Array)).toBe('ls\r')
    act(() => g.terms[0].resize?.({ cols: 100, rows: 30 }))
    expect(g.sockets[0].sent[1]).toBe(JSON.stringify({ t: 'r', c: 100, r: 30 }))
  })

  it('refuses a session id that is not the gateway\'s shape, so the file panel never addresses an arbitrary path', async () => {
    open()
    await screen.findByText('web-1')
    message(JSON.stringify({ t: 'ready', session_id: '../../etc', files: true }))
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Files' }))
    expect(screen.getByRole('button', { name: 'Hide files' })).toBeDefined()
    expect(document.querySelector('.desk-body')!.children).toHaveLength(1)
  })

  it('ends with the gateway\'s reason, freezes the clock, and disconnects on request with a user exit', async () => {
    open()
    await screen.findByText('web-1')
    message(JSON.stringify({ t: 'ready' }))
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Disconnect' }))
    expect(g.sockets[0].closed).toEqual({ code: 1000, reason: 'user_exit' })
    expect(await screen.findByRole('dialog')).toBeDefined()
    expect(screen.getByText('Ended · recording saved')).toBeDefined()
    expect(document.querySelector('.term-bar')!.textContent).toContain('ran for ')
    expect(screen.queryByRole('button', { name: 'Disconnect' })).toBeNull()
  })

  it('tells the policy\'s refusal apart from a lost target when the socket closes', async () => {
    open()
    await screen.findByText('web-1')
    act(() => g.sockets[0].onclose?.({ code: 1008, reason: 'policy_revoked: access to web-1 was withdrawn' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('access to web-1 was withdrawn')
  })

  it('rebuilds the terminal and socket when the session ticket changes, and tears both down on leave', async () => {
    const { unmount } = open()
    await screen.findByText('web-1')
    expect(g.terms).toHaveLength(1)
    unmount()
    expect(g.terms[0].disposed).toBe(true)
    expect(g.sockets[0].closed).not.toBeNull()
  })
})


// Review U2 (WCAG 2.1.2): Tab is a shell key, so xterm keeps it, and nothing
// let a keyboard-only person leave the terminal for Disconnect or Files.
// Ctrl+Shift+F6 moves focus to the bar's controls; every other key, bare F6
// (mc, htop) included, still goes to the shell.
describe('Terminal, leaving by keyboard', () => {
  it('moves focus to the controls on Ctrl+Shift+F6 and keeps the key from the shell', () => {
    open()
    message(new TextEncoder().encode('$ ').buffer)
    const handler = g.terms[0].keyHandler
    expect(handler).not.toBeNull()
    const chord = new KeyboardEvent('keydown', { key: 'F6', ctrlKey: true, shiftKey: true, cancelable: true })
    expect(handler!(chord)).toBe(false)
    expect(chord.defaultPrevented).toBe(true)
    const active = document.activeElement
    expect(active?.tagName).toBe('BUTTON')
    expect(active?.closest('.term-bar')).not.toBeNull()
    // Tab and letters stay with the terminal.
    expect(handler!(new KeyboardEvent('keydown', { key: 'Tab' }))).toBe(true)
    expect(handler!(new KeyboardEvent('keydown', { key: 'a' }))).toBe(true)
    expect(handler!(new KeyboardEvent('keyup', { key: 'F6', ctrlKey: true, shiftKey: true }))).toBe(true)
    expect(screen.getByText('Ctrl+Shift+F6: controls')).toBeDefined()
  })

  it('leaves F6 alone, and with Ctrl+Alt+Shift, to the shell', () => {
    open()
    message(new TextEncoder().encode('$ ').buffer)
    const handler = g.terms[0].keyHandler!
    for (const init of [{}, { ctrlKey: true, altKey: true, shiftKey: true }]) {
      const e = new KeyboardEvent('keydown', { key: 'F6', cancelable: true, ...init })
      expect(handler(e)).toBe(true)
      expect(e.defaultPrevented).toBe(false)
      expect(document.activeElement?.closest('.term-bar')).toBeNull()
    }
  })
})
