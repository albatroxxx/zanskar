import { act, cleanup, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Status } from 'guacamole-common-js'
import { Desktop } from './Desktop'

type Handler<T extends unknown[]> = ((...args: T) => void) | null

/** What the tests drive in place of a guacd connection. */
interface FakeClient {
  onerror: Handler<[Status]>
  onstatechange: Handler<[number]>
  tunnel: { oninstruction: Handler<[string, string[]]> }
  disconnect(): void
}

const g = vi.hoisted(() => ({ clients: [] as FakeClient[] }))

// The client and tunnel stand in for guacd; everything else is the library.
vi.mock('guacamole-common-js', async (importOriginal) => {
  const real = ((await importOriginal()) as { default: Record<string, unknown> }).default
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
    sendKeyEvent() {}
    sendMouseState() {}
    sendSize() {}
  }
  class Mouse {
    onmousedown = null
    onmouseup = null
    onmousemove = null
  }
  return { default: { ...real, WebSocketTunnel, Client, Mouse } }
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

/** connected waits for the page to load the library and open its client. */
async function connected(): Promise<FakeClient> {
  for (let i = 0; i < 100 && g.clients.length === 0; i++) {
    await act(() => new Promise((r) => setTimeout(r, 10)))
  }
  const c = g.clients.at(-1)
  if (!c) throw new Error('the desktop page never connected')
  return c
}

beforeEach(() => {
  g.clients.length = 0
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
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
    ['the user disconnects', (c: FakeClient) => c.disconnect(), 'You closed the session, or it ended on the target.', null],
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
