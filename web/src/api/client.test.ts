import { describe, expect, it, vi } from 'vitest'
import { ApiError, api, errorMessage } from './client'

// M22: every error carries the request id, which finds the gateway's log
// lines. A server error is the one a user reports, so it shows the id.
describe('errorMessage', () => {
  it('adds the reference to a server error', () => {
    const err = new ApiError(500, { code: 'internal', message: 'internal error', request_id: '3f2a9c0b1d2e4f5a' }, 'failed')
    expect(errorMessage(err)).toBe('internal error (reference 3f2a9c0b1d2e4f5a)')
  })

  it('leaves a refusal as the gateway worded it', () => {
    const err = new ApiError(409, { code: 'conflict', message: 'a target with that name exists', request_id: '3f2a9c0b1d2e4f5a' }, 'failed')
    expect(errorMessage(err)).toBe('a target with that name exists')
  })

  it('has nothing to add without an id', () => {
    expect(errorMessage(new ApiError(502, null, 'Bad Gateway'))).toBe('Bad Gateway')
  })
})

// The live console (2026-11-01): an admin page opening read the gateway's
// status three times at once, and the portal's targets page read the
// user's grants twice.
describe('api.get, the same read at once', () => {
  /** gateway answers each request when told to, and lists what reached it. */
  function gateway() {
    const waiting: ((r: Response) => void)[] = []
    const seen: string[] = []
    vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
      seen.push(`${init?.method ?? 'GET'} ${url}`)
      return new Promise<Response>((resolve) => waiting.push(resolve))
    }))
    const answer = (body: unknown, status = 200) => waiting.shift()?.(new Response(JSON.stringify(body), { status }))
    return { seen, answer }
  }

  it('asks the gateway once, and gives each caller a copy of its own', async () => {
    const g = gateway()
    const a = api.get<{ items: number[] }>('/admin/system/status')
    const b = api.get<{ items: number[] }>('/admin/system/status')
    const other = api.get('/me/access')
    expect(g.seen).toEqual(['GET /api/v1/admin/system/status', 'GET /api/v1/me/access'])
    g.answer({ items: [1, 2] })
    g.answer({ items: [] })
    const [x, y] = await Promise.all([a, b, other])
    x.items.push(3)
    expect(y.items).toEqual([1, 2])
  })

  it('shares a refusal too', async () => {
    const g = gateway()
    const a = api.get('/users')
    const b = api.get('/users')
    g.answer({ code: 'forbidden', message: 'no' }, 403)
    await expect(a).rejects.toMatchObject({ status: 403 })
    await expect(b).rejects.toMatchObject({ status: 403 })
    expect(g.seen).toHaveLength(1)
  })

  it('never answers a read asked for after a change with one from before it', () => {
    const g = gateway()
    void api.get('/users')
    void api.post('/users', { username: 'x' })
    void api.get('/users')
    // an upload is a change too
    void api.upload('/sessions/s1/files', new Blob(['x']))
    void api.get('/users')
    expect(g.seen).toEqual(['GET /api/v1/users', 'POST /api/v1/users', 'GET /api/v1/users', 'POST /api/v1/sessions/s1/files', 'GET /api/v1/users'])
  })

  it('never shares a read that started while a change was on its way with one asked for after it', async () => {
    const g = gateway()
    const change = api.post('/users', { username: 'x' })
    void api.get('/users') // a poll landing while the change is in flight
    g.answer({ id: 'u1' }) // the change is answered; the poll is not yet
    await change
    void api.get('/users') // the caller's reload after the change
    expect(g.seen).toEqual(['POST /api/v1/users', 'GET /api/v1/users', 'GET /api/v1/users'])
  })

  it('asks again once the first reply is in, or when the first has hung a second', async () => {
    const g = gateway()
    const first = api.get('/auth/me')
    g.answer({ ok: 1 })
    await first
    void api.get('/auth/me')
    expect(g.seen).toHaveLength(2)
    // that one never answers; the same read a second later asks again
    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + 1000)
    void api.get('/auth/me')
    expect(g.seen).toHaveLength(3)
  })
})
