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
  // what the terminal player was asked to do by the page's own keys
  pauses: 0,
  // the height of the terminal player's picture, as laid out
  pictureHeight: 0,
}))

vi.mock('asciinema-player', () => ({
  // Like the real one, the player draws a focusable wrapper into its host.
  create: (_src: unknown, el: HTMLElement, opts: Record<string, unknown>) => {
    h.creates.push(opts)
    const wrapper = document.createElement('div')
    wrapper.className = 'ap-wrapper'
    wrapper.tabIndex = -1
    const picture = document.createElement('div')
    picture.className = 'ap-player'
    picture.getBoundingClientRect = () => ({ height: h.pictureHeight }) as DOMRect
    wrapper.appendChild(picture)
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
      pause: async () => {
        h.pauses++
      },
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
  h.pauses = 0
  h.pictureHeight = 0
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

// The recordings list sends a reviewer here for the downloads (2026-11-01).
// A desktop recording, an application's included (ADR 0034), is a pixel
// stream with no command lines: the file, and no transcript.
describe('Player, the downloads', () => {
  it('offers the file and no transcript for a desktop recording', async () => {
    gateway({ [`/api/v1/recordings/${RID}`]: [() => json(200, recording({ format: 'guac' }))] })
    open(`/audit/recordings/${RID}`)
    expect((await screen.findByRole('link', { name: 'Download recording' })).getAttribute('href')).toBe(`/api/v1/recordings/${RID}/download`)
    expect(screen.queryByRole('link', { name: 'Download transcript' })).toBeNull()
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
    // no line of keyboard instructions under the controls (2026-11-01)
    expect(screen.queryByText(/play\/pause|full screen\./i)).toBeNull()
  })

  // The terminal player fitted the card's width only, so in a wide, short
  // window its controls were below the window's bottom (the live console,
  // 2026-11-01, 1707x692). It fits both ways now, in the room the page
  // gives it, and is never made again for full screen: it fits the stage.
  it('gives the terminal player the window less the controls on the page, and the stage in full screen', async () => {
    const asked = fullscreen()
    const user = await playTerminal()
    const room = `${window.innerHeight - 72}px`
    const host = document.querySelector<HTMLElement>('.player-host')!
    expect(h.creates.map((o) => o.fit)).toEqual(['both'])
    expect(host.style.height).toBe(room)

    act(() => h.listeners.playing())
    h.now = 5
    await user.click(screen.getByRole('button', { name: 'Full screen' }))
    expect(asked).toHaveLength(1)
    expect(asked[0].contains(screen.getByRole('combobox', { name: 'Playback speed' }))).toBe(true)
    // the stage's flex height, not the page's
    expect(host.style.height).toBe('')

    // the browser leaves full screen with the page at its top; the player
    // goes back to the top of the window, where Play put it
    const scrolled = vi.fn()
    Element.prototype.scrollIntoView = scrolled
    await user.click(screen.getByRole('button', { name: 'Exit full screen' }))
    expect(host.style.height).toBe(room)
    expect(scrolled).toHaveBeenCalledWith({ block: 'start' })
    expect(scrolled.mock.contexts[0]).toBe(host)
    // one player throughout, never moved
    expect(h.creates).toHaveLength(1)
    expect(h.seeks).toEqual([])
  })

  it('takes the room in to the picture when the width is what limits it', async () => {
    let seen: ResizeObserverCallback = () => {}
    vi.stubGlobal('ResizeObserver', class {
      constructor(cb: ResizeObserverCallback) {
        seen = cb
      }
      observe() {}
      disconnect() {}
    })
    await playTerminal()
    const host = document.querySelector<HTMLElement>('.player-host')!
    h.pictureHeight = 400.2
    act(() => seen([], {} as ResizeObserver))
    expect(host.style.height).toBe('401px')
    // a picture as tall as the room leaves it be
    host.style.height = `${window.innerHeight - 72}px`
    h.pictureHeight = window.innerHeight
    act(() => seen([], {} as ResizeObserver))
    expect(host.style.height).toBe(`${window.innerHeight - 72}px`)
  })

  // A click on Play takes its own button away, so focus fell to the page,
  // where the terminal player heard no key: Space scrolled the page and F
  // did nothing (the live console, 2026-11-01).
  it('hands focus to the terminal player on Play', async () => {
    await playTerminal()
    expect(document.activeElement?.className).toBe('ap-wrapper')
  })

  it('answers the keys from anywhere on the page for a terminal recording', async () => {
    fullscreen()
    const user = await playTerminal()
    act(() => h.listeners.playing())
    ;(document.activeElement as HTMLElement).blur()
    h.now = 3
    await user.keyboard(' ')
    expect(h.pauses).toBe(1)
    await user.keyboard('{ArrowRight}{ArrowLeft}{Home}{End}')
    expect(h.seeks).toEqual([13, 0, 0, '100%'])
    await user.keyboard('f')
    expect(screen.getByRole('button', { name: 'Exit full screen' })).toBeDefined()
  })

  it('leaves Space to a focused button, and every key to the terminal player inside it', async () => {
    const user = await playTerminal()
    act(() => h.listeners.playing())
    h.now = 30
    screen.getByRole('button', { name: 'Back 10 seconds' }).focus()
    await user.keyboard(' ')
    // the button was pressed; the page did not pause as well
    expect(h.seeks).toEqual([20])
    expect(h.pauses).toBe(0)

    document.querySelector<HTMLElement>('.ap-wrapper')!.focus()
    await user.keyboard(' {ArrowRight}')
    expect(h.pauses).toBe(0)
    expect(h.seeks).toEqual([20])
  })

  it('answers F in the terminal player, and again in full screen', async () => {
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

    // the same player, still focused, so a second F works without a click
    expect(document.activeElement).toBe(first)
    await user.keyboard('f')
    document.removeEventListener('keydown', reached)
    expect(reached).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Full screen' })).toBeDefined()
    expect(h.creates).toHaveLength(1)
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
    // no stray "desktop" badge under the playback card (2026-11-01)
    expect(screen.queryByText('desktop')).toBeNull()
  })

  // In a short window the desktop was sized to the room below where the
  // player stood (320 px down), so it came out small, and the small picture
  // kept the page too short to scroll it any higher (the live console,
  // 2026-11-01). It is sized to the window less the controls: Play scrolls
  // it to the top.
  it('sizes a desktop recording for the window, not for where the player stands before Play scrolls it', async () => {
    h.deskPlays = true
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(2000)
    vi.spyOn(window, 'innerHeight', 'get').mockReturnValue(500)
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({ top: 320, height: 0 } as DOMRect)
    gateway({ [`/api/v1/recordings/${RID}`]: [() => json(200, recording({ format: 'guac' }))] })
    open(`/audit/recordings/${RID}`)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Play' }))
    await screen.findByRole('button', { name: 'Pause' })
    // 500 high, 72 kept for the controls: 428 for a 600-high desktop
    expect(h.scales.at(-1)).toBeCloseTo(428 / 600)
    expect(document.querySelector<HTMLElement>('.player-host')!.style.height).toBe('428px')
  })
})
