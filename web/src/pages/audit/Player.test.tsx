import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { setSessionEndedHandler } from '../../api/client'
import type { Recording } from '../../api/types'
import { Player } from './Player'

// The players themselves are libraries with their own tests; what matters
// here is what the page asks them and the gateway for.
const h = vi.hoisted(() => ({
  tunnels: [] as string[],
  seeks: [] as unknown[],
  // the options each terminal player was made with, where it stands, and
  // what the latest one listens for
  creates: [] as Record<string, unknown>[],
  now: 0,
  listeners: {} as Record<string, () => void>,
  // whether the desktop recording plays or the gateway refuses its stream
  deskPlays: false,
  scales: [] as number[],
}))

vi.mock('asciinema-player', () => ({
  // Like the real one, the player draws a focusable wrapper into its host.
  create: (_src: unknown, el: HTMLElement, opts: Record<string, unknown>) => {
    h.creates.push(opts)
    const wrapper = document.createElement('div')
    wrapper.className = 'ap-wrapper'
    wrapper.tabIndex = -1
    el.appendChild(wrapper)
    return {
      addEventListener(event: string, fn: () => void) {
        h.listeners[event] = fn
      },
      dispose() {},
      seek: async (to: unknown) => {
        h.seeks.push(to)
      },
      play: async () => {},
      pause: async () => {},
      getCurrentTime: () => h.now,
    }
  },
}))

vi.mock('guacamole-common-js', () => {
  class StaticHTTPTunnel {
    constructor(url: string) {
      h.tunnels.push(url)
    }
  }
  // Stands in for a recording whose stream request the gateway refused (over
  // HTTP/2 a refusal has no status text, so the message is empty), or, with
  // h.deskPlays, for an 800x600 desktop recording that loads and plays.
  class SessionRecording {
    onerror: ((message: string) => void) | null = null
    onload: (() => void) | null = null
    onplay: (() => void) | null = null
    getDisplay() {
      const size = h.deskPlays ? [800, 600] : [0, 0]
      return { getElement: () => document.createElement('div'), getWidth: () => size[0], getHeight: () => size[1], scale: (s: number) => h.scales.push(s) }
    }
    connect() {
      setTimeout(() => (h.deskPlays ? this.onload?.() : this.onerror?.('')), 0)
    }
    play() {
      this.onplay?.()
    }
    pause() {}
    seek() {}
    getDuration() {
      return 60_000
    }
    getPosition() {
      return 0
    }
    disconnect() {}
    isPlaying() {
      return false
    }
  }
  return { default: { StaticHTTPTunnel, SessionRecording } }
})

// A recording id of the shape the gateway generates (store.NewID).
const RID = '0123456789abcdef0123456789abcdef'

const recording = (over: Partial<Recording> = {}): Recording => ({
  id: RID, session_id: 's1', format: 'asciicast', size_bytes: 10, started_at: '2026-10-06T10:00:00Z', created_at: '2026-10-06T10:00:00Z', ...over,
})

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const signedOut = () => json(401, { code: 'unauthenticated', message: 'sign in required' })

/** gateway answers the console's requests from a table of path -> responses, one per call. */
function gateway(routes: Record<string, (() => Response)[]>) {
  const seen: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    seen.push(url)
    const next = routes[url]?.shift()
    return next ? next() : json(404, { code: 'not_found', message: 'no route ' + url })
  }))
  return seen
}

function open(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/audit/recordings/:id" element={<Player />} />
      </Routes>
    </MemoryRouter>,
  )
}

let ended: ReturnType<typeof vi.fn<() => void>>
beforeEach(() => {
  h.tunnels.length = 0
  h.seeks.length = 0
  h.creates.length = 0
  h.now = 0
  h.listeners = {}
  h.deskPlays = false
  h.scales.length = 0
  // jsdom lays nothing out, so it has no scrolling to do.
  Element.prototype.scrollIntoView = () => {}
  ended = vi.fn<() => void>()
  setSessionEndedHandler(ended)
})
afterEach(() => {
  cleanup()
  setSessionEndedHandler(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  const d = document as unknown as Record<string, unknown>
  delete d.fullscreenElement
  delete d.exitFullscreen
  delete (HTMLElement.prototype as unknown as Record<string, unknown>).requestFullscreen
})

/** fullscreen stands in for the browser's Fullscreen API, which jsdom lacks:
 *  it records which element asked and announces the change like a browser. */
function fullscreen() {
  let on = false
  const request = vi.fn(() => {
    on = true
    document.dispatchEvent(new Event('fullscreenchange'))
    return Promise.resolve()
  })
  // the element each request was made on
  const asked = request.mock.contexts as HTMLElement[]
  HTMLElement.prototype.requestFullscreen = request
  Object.defineProperty(document, 'fullscreenElement', { configurable: true, get: () => (on ? asked.at(-1) : null) })
  document.exitFullscreen = () => {
    on = false
    document.dispatchEvent(new Event('fullscreenchange'))
    return Promise.resolve()
  }
  return asked
}

// B26: the player fetched the recording itself, so a session that had ended
// showed a bare error instead of the session dialog, and the recording id
// from the address went into the request paths unencoded.
describe('Player', () => {
  it('sends a session that ended while reviewing to the session dialog', async () => {
    gateway({
      [`/api/v1/recordings/${RID}`]: [() => json(200, recording())],
      [`/api/v1/recordings/${RID}/stream`]: [signedOut],
    })
    open(`/audit/recordings/${RID}`)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Play' }))

    await waitFor(() => expect(ended).toHaveBeenCalled())
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('does the same for a desktop recording', async () => {
    gateway({
      [`/api/v1/recordings/${RID}`]: [() => json(200, recording({ format: 'guac' })), signedOut],
    })
    open(`/audit/recordings/${RID}`)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Play' }))

    await waitFor(() => expect(ended).toHaveBeenCalled())
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('asks for nothing when the address holds an id the gateway never makes', async () => {
    const seen = gateway({})
    for (const bad of ['%2E%2E', 'a%2F..%2Fb', 'r1']) {
      open('/audit/recordings/' + bad)
      expect(await screen.findByText('There is no recording with that id.')).toBeDefined()
      cleanup()
    }
    expect(seen).toEqual([])
  })

  it('encodes the id in every path it builds', async () => {
    const seen = gateway({
      [`/api/v1/recordings/${RID}`]: [() => json(200, recording())],
      [`/api/v1/recordings/${RID}/stream`]: [() => new Response('{"version": 2}\n')],
    })
    open(`/audit/recordings/${RID}`)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Play' }))

    await waitFor(() => expect(seen).toContain(`/api/v1/recordings/${RID}/stream`))
    expect(screen.getByRole('link', { name: 'Download recording' }).getAttribute('href')).toBe(`/api/v1/recordings/${RID}/download`)
    expect(screen.getByRole('link', { name: 'Download transcript' }).getAttribute('href')).toBe(`/api/v1/recordings/${RID}/transcript`)
  })
})

// B28: the command list was clickable <li>s, so a keyboard user could not
// jump the playback to a command. Each command is a button now.
describe('Player, the command list', () => {
  it('jumps the playback to a command from the keyboard', async () => {
    const cast = ['{"version": 2, "width": 80, "height": 24}', '[1.0, "m", "ls -la"]', '[2.5, "m", "whoami"]', '[3.0, "m", "(hidden input)"]'].join('\n')
    gateway({
      [`/api/v1/recordings/${RID}`]: [() => json(200, recording())],
      [`/api/v1/recordings/${RID}/stream`]: [() => new Response(cast)],
    })
    open(`/audit/recordings/${RID}`)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Play' }))

    const whoami = await screen.findByRole('button', { name: /whoami/ })
    expect(screen.getByRole('button', { name: /hidden input/ })).toBeDefined()
    whoami.focus()
    await user.keyboard('{Enter}')

    expect(h.seeks).toEqual([{ marker: 1 }])
  })
})

// The player's controls were words (Replay, −10s, Play, +10s) and it had no
// full screen of its own (the live console, 2026-10-31).
describe('Player, the transport', () => {
  const cast = ['{"version": 2, "width": 80, "height": 24}', '[1.0, "o", "a"]', '[2.0, "o", "b"]', '[8.0, "o", "c"]'].join('\n')

  async function playTerminal() {
    gateway({
      [`/api/v1/recordings/${RID}`]: [() => json(200, recording())],
      [`/api/v1/recordings/${RID}/stream`]: [() => new Response(cast)],
    })
    open(`/audit/recordings/${RID}`)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Play' }))
    await screen.findByRole('button', { name: 'Full screen' })
    return user
  }

  it('shows each control as a glyph and keeps its words in the name', async () => {
    const user = await playTerminal()
    for (const name of ['Play again from the start', 'Back 10 seconds', 'Play', 'Forward 10 seconds', 'Full screen']) {
      const b = screen.getByRole('button', { name })
      expect(b.textContent).toBe('')
      expect(b.querySelector('svg')).not.toBeNull()
      expect(b.getAttribute('title')).toBe(name)
    }
    h.now = 3
    await user.click(screen.getByRole('button', { name: 'Forward 10 seconds' }))
    await user.click(screen.getByRole('button', { name: 'Back 10 seconds' }))
    expect(h.seeks).toEqual([13, 0])
  })

  it('takes a paused terminal player and its controls full screen and back, on the same frame', async () => {
    const asked = fullscreen()
    const user = await playTerminal()
    expect(h.creates.map((o) => o.fit)).toEqual(['width'])

    // 5 s on the player's clock is 9 s into the recording: the 6 s gap
    // before the last event was squeezed to 2.
    h.now = 5
    await user.click(screen.getByRole('button', { name: 'Full screen' }))
    expect(asked).toHaveLength(1)
    expect(asked[0].contains(screen.getByRole('combobox', { name: 'Playback speed' }))).toBe(true)
    expect(h.creates.map((o) => o.fit)).toEqual(['width', 'both'])
    expect(h.creates[1]).toMatchObject({ startAt: 9, autoPlay: false })
    // paused, the new player is moved to the frame the old one showed
    expect(h.seeks).toEqual([5])

    await user.click(screen.getByRole('button', { name: 'Exit full screen' }))
    expect(h.creates.map((o) => o.fit)).toEqual(['width', 'both', 'width'])
    expect(h.seeks).toEqual([5, 5])
  })

  it('keeps a playing terminal player playing in full screen, without a seek', async () => {
    fullscreen()
    const user = await playTerminal()
    act(() => h.listeners.playing())
    await user.click(screen.getByRole('button', { name: 'Full screen' }))
    expect(h.creates[1]).toMatchObject({ fit: 'both', autoPlay: true })
    expect(h.seeks).toEqual([])
  })

  it('answers F in the terminal player, and again in the player made for full screen', async () => {
    fullscreen()
    const user = await playTerminal()
    // The terminal player's own F would take only the picture full screen,
    // so the key never reaches it (its keys are delegated to the document).
    const reached = vi.fn()
    document.addEventListener('keydown', reached)
    const first = document.querySelector<HTMLElement>('.ap-wrapper')!
    first.focus()
    await user.keyboard('f')
    expect(screen.getByRole('button', { name: 'Exit full screen' })).toBeDefined()

    // Focus went to the new player, so a second F works without a click.
    const second = document.activeElement as HTMLElement
    expect(second).not.toBe(first)
    expect(second.className).toBe('ap-wrapper')
    await user.keyboard('f')
    document.removeEventListener('keydown', reached)
    expect(reached).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Full screen' })).toBeDefined()
    expect(h.creates.map((o) => o.fit)).toEqual(['width', 'both', 'width'])
  })

  it('draws a desktop recording as large as the screen in full screen, never above its size on the page', async () => {
    const asked = fullscreen()
    h.deskPlays = true
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(2000)
    vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(1000)
    gateway({ [`/api/v1/recordings/${RID}`]: [() => json(200, recording({ format: 'guac' }))] })
    open(`/audit/recordings/${RID}`)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Play' }))
    // playing, the toggle shows the pause bars rather than the play triangle
    const pause = await screen.findByRole('button', { name: 'Pause' })
    expect(pause.querySelectorAll('rect')).toHaveLength(2)
    expect(pause.querySelector('polygon')).toBeNull()
    expect(h.scales.at(-1)).toBe(1)

    await user.click(screen.getByRole('button', { name: 'Full screen' }))
    expect(asked[0].contains(screen.getByRole('slider', { name: 'Playback position' }))).toBe(true)
    // the stage is 1000 high; 72 of it is kept for the controls
    await waitFor(() => expect(h.scales.at(-1)).toBeCloseTo(928 / 600))

    // the desktop's keys work from anywhere on the page, not only the stage
    ;(document.activeElement as HTMLElement).blur()
    await user.keyboard('f')
    await waitFor(() => expect(h.scales.at(-1)).toBe(1))
    expect(screen.getByRole('button', { name: 'Full screen' })).toBeDefined()
  })
})
