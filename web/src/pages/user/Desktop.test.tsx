import { act, cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Status } from 'guacamole-common-js'
import { api } from '../../api/client'
import { Desktop } from './Desktop'

type Handler<T extends unknown[]> = ((...args: T) => void) | null

/** What the tests drive in place of a guacd connection. */
interface FakeClient {
  keys: number[]
  onerror: Handler<[Status]>
  onstatechange: Handler<[number]>
  tunnel: { oninstruction: Handler<[string, string[]]> }
  disconnect(): void
}

/** The part of the library's own keyboard the tests look at. */
interface RealKeyboard { onkeydown: unknown; onkeyup: unknown }

const g = vi.hoisted(() => ({ clients: [] as FakeClient[], keyboards: [] as RealKeyboard[] }))

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
  }
  class Client {
    onerror: Handler<[Status]> = null
    onstatechange: Handler<[number]> = null
    onfilesystem = null
    onclipboard = null
    private display = document.createElement('div')
    tunnel: WebSocketTunnel
    constructor(tunnel: WebSocketTunnel) {
      this.tunnel = tunnel
      g.clients.push(this)
    }
    getDisplay() {
      return { getElement: () => this.display }
    }
    connect() {
      this.tunnel.oninstruction = () => {}
    }
    disconnect() {
      this.onstatechange?.(5)
    }
    keys: number[] = []
    sendKeyEvent(_pressed: number, k: number) { this.keys.push(k) }
    sendMouseState() {}
    sendSize() {}
  }
  class Mouse {
    onmousedown = null
    onmouseup = null
    onmousemove = null
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
      </Routes>
    </MemoryRouter>,
  )
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
    expect(within(screen.getByRole('dialog')).getByText(/win-01 · RDP · ran for 00:03\./)).toBeDefined()
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
// keyboard-only person could not reach Disconnect. F6 moves focus to the
// bar and is not sent to the remote machine; the browser keeps the key.
describe('Desktop, leaving by keyboard', () => {
  it('moves focus to the controls on F6', async () => {
    start()
    const client = await connected()
    const kb = g.keyboards[0] as unknown as { onkeydown: (k: number) => boolean }
    const sentBefore = client.keys.length
    let kept = false
    act(() => { kept = kb.onkeydown(0xffc3) })
    expect(kept).toBe(true)
    expect(client.keys.length).toBe(sentBefore)
    const active = document.activeElement
    expect(active?.tagName).toBe('BUTTON')
    expect(active?.closest('.term-bar')).not.toBeNull()
    expect(screen.getByText('F6: controls')).toBeDefined()
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
