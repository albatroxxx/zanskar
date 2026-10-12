import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { setSessionEndedHandler } from '../../api/client'
import type { Recording } from '../../api/types'
import { Player } from './Player'

// The players themselves are libraries with their own tests; what matters
// here is what the page asks them and the gateway for.
const h = vi.hoisted(() => ({ tunnels: [] as string[] }))

vi.mock('asciinema-player', () => ({
  create: () => ({ addEventListener() {}, dispose() {}, seek: async () => {}, play: async () => {}, pause: async () => {}, getCurrentTime: () => 0 }),
}))

vi.mock('guacamole-common-js', () => {
  class StaticHTTPTunnel {
    constructor(url: string) {
      h.tunnels.push(url)
    }
  }
  // Stands in for a recording whose stream request the gateway refused.
  // Over HTTP/2 a refusal has no status text, so the message is empty.
  class SessionRecording {
    onerror: ((message: string) => void) | null = null
    getDisplay() {
      return { getElement: () => document.createElement('div'), getWidth: () => 0, getHeight: () => 0, scale() {} }
    }
    connect() {
      setTimeout(() => this.onerror?.(''), 0)
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
  // jsdom lays nothing out, so it has no scrolling to do.
  Element.prototype.scrollIntoView = () => {}
  ended = vi.fn<() => void>()
  setSessionEndedHandler(ended)
})
afterEach(() => {
  cleanup()
  setSessionEndedHandler(null)
  vi.unstubAllGlobals()
})

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
