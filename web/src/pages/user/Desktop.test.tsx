import { act, cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Status } from 'guacamole-common-js'
import { api } from '../../api/client'
import { Desktop } from './Desktop'
import { takeIntent } from './intent'

type Handler<T extends unknown[]> = ((...args: T) => void) | null

/** What the tests drive in place of a guacd connection. */
interface FakeClient {
  keys: number[]
  /** Mouse states sent to the remote machine. */
  moves: number
  display: FakeDisplay
  onerror: Handler<[Status]>
  onstatechange: Handler<[number]>
  tunnel: { oninstruction: Handler<[string, string[]]> }
  disconnect(): void
}

/** The part of the library's own keyboard the tests look at. */
interface RealKeyboard { onkeydown: unknown; onkeyup: unknown }

/** The mouse on the desktop's display, as the page wires it. */
interface FakeMouse {
  onmousedown: ((m: unknown) => void) | null
  onmousemove: ((m: unknown) => void) | null
  onmouseout: ((m: unknown) => void) | null
  /** Each setCursor call: the canvas and its hotspot. */
  cursors: [HTMLCanvasElement, number, number][]
}

/** The remote display: its element, the cursor callback the page sets, and
 *  each showCursor call (true shows the software cursor). */
interface FakeDisplay {
  el: HTMLElement
  oncursor: ((canvas: HTMLCanvasElement, x: number, y: number) => void) | null
  shown: boolean[]
}

// cursorOK is what the fake Mouse.setCursor answers: whether the browser takes
// an image cursor.
const g = vi.hoisted(() => ({ clients: [] as FakeClient[], keyboards: [] as RealKeyboard[], mice: [] as FakeMouse[], cursorOK: true, tunnels: [] as string[] }))

// The client and tunnel stand in for guacd; everything else is the library,
// the keyboard included, so its hold on the document's keys is the real one.
vi.mock('guacamole-common-js', async (importOriginal) => {
  const real = ((await importOriginal()) as { default: Record<string, unknown> }).default
  const RealKeyboard = real.Keyboard as new (el: Document) => RealKeyboard
  class Keyboard extends RealKeyboard {
    constructor(el: Document) {
      super(el)
      g.keyboards.push(this)
    }
  }
  class WebSocketTunnel {
    oninstruction: Handler<[string, string[]]> = null
    onerror: Handler<[Status]> = null
    constructor(url: string) { g.tunnels.push(url) }
  }
  class Client {
    onerror: Handler<[Status]> = null
    onstatechange: Handler<[number]> = null
    onfilesystem = null
    onclipboard = null
    display = {
      el: document.createElement('div'),
      oncursor: null as FakeDisplay['oncursor'],
      shown: [] as boolean[],
      getElement() { return this.el },
      showCursor(shown = true) { this.shown.push(shown) },
    }
    tunnel: WebSocketTunnel
    constructor(tunnel: WebSocketTunnel) {
      this.tunnel = tunnel
      g.clients.push(this)
    }
    getDisplay() {
      return this.display
    }
    connect() {
      this.tunnel.oninstruction = () => {}
    }
    disconnect() {
      this.onstatechange?.(5)
    }
    keys: number[] = []
    sendKeyEvent(_pressed: number, k: number) { this.keys.push(k) }
    moves = 0
    sendMouseState() { this.moves++ }
    sendSize() {}
  }
  class Mouse {
    onmousedown = null
    onmouseup = null
    onmousemove = null
    onmouseout = null
    cursors: [HTMLCanvasElement, number, number][] = []
    private el: HTMLElement
    constructor(el: HTMLElement) {
      this.el = el
      g.mice.push(this)
    }
    setCursor(canvas: HTMLCanvasElement, x: number, y: number) {
      this.cursors.push([canvas, x, y])
      if (g.cursorOK) this.el.style.cursor = `url(data:image/png;base64,AA) ${x} ${y}, auto`
      return g.cursorOK
    }
  }
  return { default: { ...real, WebSocketTunnel, Client, Mouse, Keyboard } }
})

const desk = { ticket: 'tk1', ws_path: '/ws/desktop', target: 'win-01', protocol: 'rdp' }

function start(state: object = desk) {
  render(
    <MemoryRouter initialEntries={[{ pathname: '/desktop', state }]}>
      <Routes>
        <Route path="/desktop" element={<Desktop />} />
        <Route path="/" element={<p>Targets page</p>} />
        <Route path="/connect" element={<ConnectStandIn />} />
      </Routes>
    </MemoryRouter>,
  )
}

function ConnectStandIn() {
  const loc = useLocation()
  return <p>Connect page {loc.pathname + loc.search}</p>
}

/** connected waits for the page to load the library and open its nth client. */
async function connected(nth = 1): Promise<FakeClient> {
  for (let i = 0; i < 100 && g.clients.length < nth; i++) {
    await act(() => new Promise((r) => setTimeout(r, 10)))
  }
  const c = g.clients[nth - 1]
  if (!c) throw new Error(`the desktop page never opened client ${nth}`)
  return c
}

beforeEach(() => {
  g.clients.length = 0
  g.keyboards.length = 0
  g.mice.length = 0
  g.cursorOK = true
  g.tunnels.length = 0
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

// An application's browser can take a while to start, and the pane is black
// until guacd draws; the bar says so until the client reports it connected.
describe('Desktop, while connecting', () => {
  it('says so until the first frame, and not after', async () => {
    start()
    const c = await connected()
    expect(screen.getByRole('status').textContent).toContain('Connecting')
    act(() => c.onstatechange?.(3))
    expect(screen.queryByRole('status')).toBeNull()
  })
})

// B23: the desktop page's clock kept running after the session ended, and
// its end dialog printed the gateway's raw words or a reason code where the
// terminal page explains in sentences.
describe('Desktop, when the session ends', () => {
  it('stops the clock', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
    start()
    const client = await connected()
    act(() => vi.advanceTimersByTime(3000))
    expect(screen.getByText('elapsed 00:03')).toBeDefined()

    act(() => client.onerror?.({ code: 0x020b, message: 'session ended by an administrator' }))
    act(() => vi.advanceTimersByTime(5000))

    expect(screen.getByText(/^(elapsed|ran for) /).textContent).toBe('ran for 00:03')
    expect(screen.getByText('Ended · recording saved')).toBeDefined()
    expect(within(screen.getByRole('dialog')).getByText('win-01 · RDP · ran for 00:03.')).toBeDefined()
    // How long recordings are kept is the administrator's business, not news
    // for the person whose session just ended.
    expect(screen.getByRole('dialog').textContent).not.toContain('retention')
  })

  it.each([
    ['the user disconnects', (c: FakeClient) => c.disconnect(), 'You closed the session.', null],
    ['the gateway ends it (523)', (c: FakeClient) => c.onerror?.({ code: 0x020b, message: 'session ended by an administrator' }), 'Session ended by an administrator.', null],
    ['the target is lost (519)', (c: FakeClient) => c.onerror?.({ code: 0x0207, message: 'connection to the target was lost' }), 'The connection to the target was lost.', 'connection to the target was lost'],
    ['guacd refuses the login', (c: FakeClient) => c.onerror?.({ code: 0x0301, message: 'Authentication failure' }), 'The session ended because of an error.', 'Authentication failure'],
  ])('says why in a sentence when %s', async (_, end, lead, detail) => {
    start()
    const client = await connected()
    act(() => end(client))

    const dialog = screen.getByRole('dialog', { name: 'Session ended' })
    expect(dialog.querySelector('p')?.textContent).toBe(lead)
    if (detail) expect(within(dialog).getByText(detail)).toBeDefined()
  })
})

const SESSION = '0123456789abcdef0123456789abcdef'

/** press focuses a button in the open dialog and presses Enter on it, as a
 *  keyboard user would, after checking nothing swallows the key: the
 *  library swallows one by preventing its default, the click. */
async function press(name: string) {
  const button = within(screen.getByRole('dialog')).getByRole('button', { name })
  button.focus()
  const probe = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })
  button.dispatchEvent(probe)
  expect(probe.defaultPrevented, 'Enter was swallowed').toBe(false)
  await userEvent.setup().keyboard('{Enter}')
}

// B27: Guacamole.Keyboard listens on the whole document and swallows the
// keys it handles. The page let go of it only when it was left, so once a
// session ended, the dialog it showed could not be used from the keyboard.
describe('Desktop, the keyboard', () => {
  it('reaches the end dialog once the session has ended', async () => {
    start()
    const client = await connected()
    act(() => client.disconnect())

    await press('Back to targets')

    expect(screen.getByText('Targets page')).toBeDefined()
  })

  // A session runs in a tab of its own (ADR 0038); ended, the tab offered
  // only a second targets list (the live console, 2026-11-01).
  it('connects again from the end dialog, through the connect page, in this tab', async () => {
    const again = '/connect?target=t1&protocol=rdp'
    start({ ...desk, again })
    const client = await connected()
    act(() => client.disconnect())
    await press('Connect again')
    expect(screen.getByText(`Connect page ${again}`)).toBeDefined()
    // the record a session link leaves, so the connect page connects at once
    expect(takeIntent(again)).toBe(true)
  })

  it('offers no Connect again without a connect page to go back to, or with one of another shape', async () => {
    for (const again of [undefined, '/admin/users', 'https://elsewhere.example/connect?target=t1&protocol=rdp', '/connect?target=..%2Fx&protocol=rdp', '/connect?target=t1&protocol=telnet']) {
      start({ ...desk, again })
      const client = await connected()
      act(() => client.disconnect())
      const dialog = within(screen.getByRole('dialog', { name: 'Session ended' }))
      expect(dialog.queryByRole('button', { name: 'Connect again' })).toBeNull()
      expect(dialog.getByRole('button', { name: 'Back to targets' }).className).toBe('btn primary')
      cleanup()
      g.clients.length = 0
    }
  })

  it('reaches the failover dialog when the instance is lost', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    start({ ...desk, asg_id: 'g1', instance_label: 'i-0abc' })
    const client = await connected()
    act(() => client.tunnel.oninstruction?.('', [SESSION]))
    act(() => client.onerror?.({ code: 0x0207, message: 'the instance left the healthy pool' }))
    await screen.findByRole('dialog', { name: 'No healthy instances' })

    await press('Exit')

    expect(screen.getByText('Targets page')).toBeDefined()
  })

  it('is let go when the page is left, and on a failover to another instance', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ items: [{ id: 'i2', instance_id: 'i-0def', availability_zone: 'eu-west-1a', launched_at: '2026-10-06T10:00:00Z' }] } as never)
    vi.spyOn(api, 'post').mockResolvedValue({ ticket: 'tk2', ws_path: '/ws/desktop', asg_id: 'g1', asg_instance_id: 'i2', instance_label: 'i-0def' } as never)
    start({ ...desk, asg_id: 'g1', instance_label: 'i-0abc' })
    const first = await connected()
    act(() => first.tunnel.oninstruction?.('', [SESSION]))
    act(() => first.onerror?.({ code: 0x0207, message: 'the instance left the healthy pool' }))
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Switch to newest' }))

    await connected(2)
    expect(g.keyboards).toHaveLength(2)
    expect(g.keyboards[0]).toMatchObject({ onkeydown: null, onkeyup: null })
    expect(g.keyboards[1].onkeydown).not.toBeNull()

    cleanup()
    expect(g.keyboards[1]).toMatchObject({ onkeydown: null, onkeyup: null })
  })
})

// Q7: the terminal page accepts only a session id of the shape the gateway
// generates, since the id goes into API paths; the desktop page took
// anything, and a failover would have used it.
describe('Desktop, the session id from the gateway', () => {
  it('is used only when it has the shape the gateway generates', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    start({ ...desk, asg_id: 'g1' })
    const client = await connected()
    act(() => client.tunnel.oninstruction?.('', ['../../admin/logs']))
    act(() => client.onerror?.({ code: 0x0207, message: 'the instance left the healthy pool' }))

    expect(screen.getByRole('dialog').querySelector('h2')?.textContent).toBe('Session ended')
    expect(get).not.toHaveBeenCalled()
  })
})


// Review U2: the Guacamole keyboard holds the whole document, so a
// keyboard-only person could not reach Disconnect. Ctrl+Shift+F6 moves focus
// to the bar, and from there Tab, Enter and Space work the controls (1.6 to
// 1.10 moved focus but sent those keys to the remote machine, so no control
// could be used). Bare F6 (1.6 to 1.10) is the remote side's: Chromium and
// Windows use it.
describe('Desktop, leaving by keyboard', () => {
  type Kb = { onkeydown: (k: number) => boolean; modifiers: { ctrl: boolean; shift: boolean; alt: boolean; meta: boolean } }
  const F6 = 0xffc3
  const ENTER = 0xff0d
  const TAB = 0xff09
  const A = 0x61
  const hold = (kb: Kb, m: Partial<Kb['modifiers']>) => Object.assign(kb.modifiers, { ctrl: false, shift: false, alt: false, meta: false }, m)
  const press = (kb: Kb, k: number, m: Partial<Kb['modifiers']> = {}) => {
    hold(kb, m)
    let kept = false
    act(() => { kept = kb.onkeydown(k) })
    return kept
  }
  // The keys go out through the page's queue, a promise chain.
  const flush = () => act(() => new Promise((r) => setTimeout(r, 0)))
  const onBar = () => document.activeElement?.closest('.term-bar') ?? null

  it('moves focus to the controls on Ctrl+Shift+F6, and the remote machine sees the whole keystroke', async () => {
    start()
    const client = await connected()
    const kb = g.keyboards[0] as unknown as Kb
    const sentBefore = client.keys.length
    expect(press(kb, F6, { ctrl: true, shift: true })).toBe(true)
    expect(document.activeElement?.tagName).toBe('BUTTON')
    expect(onBar()).not.toBeNull()
    // F6 follows the Ctrl and Shift already sent: a bare Ctrl+Shift is
    // Windows' keyboard-layout switch.
    await flush()
    expect(client.keys.slice(sentBefore)).toEqual([F6])
    expect(screen.getByText('Ctrl+Shift+F6: controls')).toBeDefined()
  })

  it('works the controls from the keyboard until Ctrl+Shift+F6 again', async () => {
    start()
    const client = await connected()
    const kb = g.keyboards[0] as unknown as Kb
    const sentBefore = client.keys.length
    press(kb, F6, { ctrl: true, shift: true })
    // The page keeps Enter and Tab, so the browser presses and moves.
    expect(press(kb, ENTER)).toBe(true)
    expect(press(kb, TAB)).toBe(true)
    expect(press(kb, A)).toBe(true)
    // The keystroke again hands the keyboard back to the desktop.
    expect(press(kb, F6, { ctrl: true, shift: true })).toBe(true)
    expect(onBar()).toBeNull()
    expect(press(kb, A)).toBe(false)
    await flush()
    expect(client.keys.slice(sentBefore)).toEqual([F6, A])
  })

  it('hands the keys back on a click on the desktop or when focus leaves the page', async () => {
    start()
    const client = await connected()
    const kb = g.keyboards[0] as unknown as Kb
    press(kb, F6, { ctrl: true, shift: true })
    act(() => g.mice[0].onmousedown?.({}))
    expect(onBar()).toBeNull()
    expect(press(kb, A)).toBe(false)

    press(kb, F6, { ctrl: true, shift: true })
    act(() => (document.activeElement as HTMLElement).blur())
    expect(press(kb, A)).toBe(false)
    await flush()
    expect(client.keys.filter((k) => k === A)).toHaveLength(2)
  })

  it('still sends typing to the desktop after a control is clicked with the mouse', async () => {
    start()
    const client = await connected()
    const kb = g.keyboards[0] as unknown as Kb
    const sentBefore = client.keys.length
    act(() => screen.getByRole('button', { name: 'Disconnect' }).focus())
    expect(press(kb, A)).toBe(false)
    await flush()
    expect(client.keys.slice(sentBefore)).toEqual([A])
  })

  it('sends F6 alone, and with Ctrl+Alt+Shift, to the remote machine', async () => {
    start()
    const client = await connected()
    const kb = g.keyboards[0] as unknown as Kb
    const sentBefore = client.keys.length
    for (const m of [{}, { ctrl: true, alt: true, shift: true }]) {
      hold(kb, m)
      let kept = true
      act(() => { kept = kb.onkeydown(F6) })
      expect(kept).toBe(false)
      expect(document.activeElement?.closest('.term-bar')).toBeNull()
    }
    // The keys go out through the page's queue, a promise chain.
    await act(() => new Promise((r) => setTimeout(r, 0)))
    expect(client.keys.slice(sentBefore)).toEqual([F6, F6])
  })
})

// ADR 0037: an application's browser is a full Chromium with its own
// toolbar, so the bar above its pane offers no browser controls of its own
// (1.7.2 to 1.9 had Back, Forward, Reload and Home there for kiosk mode).
describe('Desktop, an application', () => {
  it('leaves browsing to the browser\'s own toolbar', async () => {
    start({ ticket: 'tk2', ws_path: '/ws/desktop', target: 'Wiki', protocol: 'http' })
    await connected()
    expect(screen.queryByRole('group', { name: 'Browser' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Back' })).toBeNull()
  })
})

// 2026-11-01: two cursors over a desktop that did not line up. The remote
// pointer is now the browser's own cursor over the desktop, as Guacamole's
// own client does it, and the library's software cursor is never shown
// beside it: only in its place, for a pointer image the browser will not take.
describe('Desktop, the pointer', () => {
  const canvas = (w: number, h: number) => Object.assign(document.createElement('canvas'), { width: w, height: h })
  const last = (shown: boolean[]) => shown[shown.length - 1]

  it('shows the remote pointer as the browser cursor and no second one', async () => {
    start()
    const client = await connected()
    const d = client.display
    const mouse = g.mice[0]
    const arrow = canvas(32, 32)
    act(() => d.oncursor?.(arrow, 4, 7))
    expect(mouse.cursors).toEqual([[arrow, 4, 7]])
    expect(d.el.style.cursor).toContain('url(')
    expect(last(d.shown)).toBe(false)
    act(() => mouse.onmousemove?.({}))
    expect(client.moves).toBe(1)
    expect(last(d.shown)).toBe(false)
  })

  it.each([
    ['too big for a browser cursor', 200, 200, true, 0],
    ['empty, the remote hiding its pointer', 0, 0, true, 0],
    ['refused by a browser without image cursors', 32, 32, false, 1],
  ])('falls back to the software cursor, the browser\'s hidden, for an image %s', async (_, w, h, ok, tried) => {
    g.cursorOK = ok
    start()
    const client = await connected()
    const d = client.display
    act(() => d.oncursor?.(canvas(w, h), 0, 0))
    expect(g.mice[0].cursors).toHaveLength(tried)
    expect(d.el.style.cursor).toBe('none')
    expect(last(d.shown)).toBe(true)
    act(() => g.mice[0].onmousemove?.({}))
    expect(last(d.shown)).toBe(true)
  })

  it('hides the software cursor while the pointer is outside the desktop', async () => {
    start()
    const client = await connected()
    const d = client.display
    act(() => d.oncursor?.(canvas(200, 200), 0, 0))
    act(() => g.mice[0].onmouseout?.({}))
    expect(last(d.shown)).toBe(false)
    act(() => g.mice[0].onmousemove?.({}))
    expect(last(d.shown)).toBe(true)
  })

  it('hands the pointer back when the session ends, and sends no more', async () => {
    start()
    const client = await connected()
    const d = client.display
    act(() => d.oncursor?.(canvas(32, 32), 0, 0))
    act(() => client.onerror?.({ code: 0x020b, message: 'session ended by an administrator' }))
    expect(d.el.style.cursor).toBe('')
    expect(last(d.shown)).toBe(false)
    act(() => g.mice[0].onmousemove?.({}))
    expect(client.moves).toBe(0)
  })
})

// 2026-11-01: on a screen or zoom with a pixel ratio of 1.5 (Brave on the
// admin's Mac) a Windows desktop filled two thirds of its pane. guacd sizes
// an RDP session at width x 96 / the DPI it is told, and the page drew it one
// remote pixel per CSS pixel; it now says 96 DPI whatever the screen.
describe('Desktop, the size it asks for', () => {
  it('asks for the pane in CSS pixels at 96 DPI on a high-density screen', async () => {
    vi.stubGlobal('devicePixelRatio', 1.5)
    start()
    await connected()
    const url = new URL(g.tunnels[0])
    expect(url.searchParams.get('dpi')).toBe('96')
    expect(url.searchParams.get('width')).toBe('1024')
    expect(url.searchParams.get('height')).toBe('768')
  })
})
