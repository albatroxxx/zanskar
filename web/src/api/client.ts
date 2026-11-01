import type { ApiErrorBody } from './types'

export class ApiError extends Error {
  status: number
  code: string
  requestId?: string
  /**
   * True when the gateway refused the call because the session is gone, rather
   * than because of anything the page asked for. The session dialog says so
   * once; a page has nothing useful to add, so errorMessage stays quiet.
   */
  sessionEnded = false
  constructor(status: number, body: ApiErrorBody | null, fallback: string) {
    super(body?.message ?? fallback)
    this.status = status
    this.code = body?.code ?? 'error'
    this.requestId = body?.request_id
  }
}

let csrfToken = ''

/**
 * Notified when the gateway refuses a call because the session is no longer
 * valid. Pages still receive the error so they can stop their own spinners;
 * this is what lets the app say what happened once, in one place, instead of
 * leaving a bare "sign in required" inside whichever page was loading.
 */
type SessionEndedHandler = () => void
let onSessionEnded: SessionEndedHandler | null = null

export function setSessionEndedHandler(fn: SessionEndedHandler | null) {
  onSessionEnded = fn
}

/** setCsrf stores the session-bound token returned by login and /auth/me. */
export function setCsrf(token: string) {
  csrfToken = token
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

/** A reply read to the end, so more than one caller can parse it. */
interface Reply { status: number; statusText: string; ok: boolean; text: string }

/**
 * Reads in flight, by path. The same read asked for again before the first
 * has answered shares its reply: an admin page opening read the gateway's
 * status three times at once (the corner's update bell, the restart notice
 * and the dashboard), and the portal's targets page read the user's grants
 * twice (the live console, 2026-11-01). Nothing is kept once the reply is
 * in, and any change made through the client forgets the reads in flight,
 * so a read asked for after a change never gets an answer from before it.
 * Only a read started in the last JOIN_MS is shared: one that hangs (a
 * session check while the machine slept) must not hold every later attempt.
 */
const inflight = new Map<string, { reply: Promise<Reply>; at: number }>()
const JOIN_MS = 1000

/** forgetReads stops sharing every read in flight. Tests call it between cases. */
export function forgetReads() {
  inflight.clear()
}

async function send(method: Method, path: string, body?: unknown): Promise<Reply> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken
  const res = await fetch('/api/v1' + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return { status: res.status, statusText: res.statusText, ok: res.ok, text: res.status === 204 ? '' : await res.text() }
}

function read(path: string): Promise<Reply> {
  const now = Date.now()
  const open = inflight.get(path)
  if (open && now - open.at < JOIN_MS) return open.reply
  const mine = { reply: send('GET', path), at: now }
  const done = () => {
    if (inflight.get(path) === mine) inflight.delete(path)
  }
  mine.reply.then(done, done)
  inflight.set(path, mine)
  return mine.reply
}

/** change sends a change, forgetting the reads in flight before it and again
 *  once it is answered: a read that started while the change was on its way
 *  may hold an answer from before it, and the caller's next read must not
 *  join that one. */
async function change(method: Method, path: string, body?: unknown): Promise<Reply> {
  forgetReads()
  try {
    return await send(method, path, body)
  } finally {
    forgetReads()
  }
}

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const res = method === 'GET' ? await read(path) : await change(method, path, body)
  if (res.status === 204) return undefined as T
  // Parsed per caller: no caller sees another's changes to the result.
  const parsed = parseBody(res.text)
  if (!res.ok) raise(res, parsed, path)
  return parsed as T
}

/** parseBody reads a reply's JSON: null when it has none or it is not JSON. */
function parseBody(text: string): unknown {
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/**
 * raise throws a refused call as an ApiError. A 401 from /auth is a failed
 * sign-in or the unauthenticated probe on startup, both of which the login
 * page reports itself. Anywhere else it means the session this page was
 * relying on has gone.
 */
function raise(res: Pick<Response, 'status' | 'statusText'>, parsed: unknown, path: string): never {
  const err = new ApiError(res.status, parsed as ApiErrorBody | null, `${res.status} ${res.statusText}`)
  if (res.status === 401 && !path.startsWith('/auth/')) {
    err.sessionEnded = true
    onSessionEnded?.()
  }
  throw err
}

/** download fetches a binary resource as a Blob, authenticated by the session
 *  cookie. Used for SSH/SFTP file downloads, which are not JSON. */
async function download(path: string): Promise<Blob> {
  const res = await fetch('/api/v1' + path, { method: 'GET', credentials: 'same-origin' })
  if (!res.ok) raise(res, parseBody(await res.text().catch(() => '')), path)
  return res.blob()
}

/** upload sends a raw body (e.g. a File) with the CSRF header and returns the
 *  parsed JSON reply. Used for SSH/SFTP file uploads. */
async function upload<T>(path: string, body: BodyInit, contentType = 'application/octet-stream'): Promise<T> {
  forgetReads()
  const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': contentType }
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken
  let text: string
  let res: Response
  try {
    res = await fetch('/api/v1' + path, { method: 'POST', headers, credentials: 'same-origin', body })
    text = await res.text()
  } finally {
    // as for any change: a read that started meanwhile is not joined
    forgetReads()
  }
  const parsed = parseBody(text)
  if (!res.ok) raise(res, parsed, path)
  return parsed as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
  download,
  upload,
}

/** query builds a query string from defined, non-empty values. */
export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    q.set(k, String(v))
  }
  const s = q.toString()
  return s ? '?' + s : ''
}

/**
 * True when a sign-in step was refused because the half-finished sign-in is
 * gone (too many wrong codes, or it expired), as opposed to a wrong code.
 */
export function signInEnded(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401 && e.code !== 'invalid_code'
}

export function errorMessage(err: unknown): string {
  // An expired session is announced once, by the session dialog. Repeating it
  // as an error banner inside the page would only be noise behind that dialog.
  if (err instanceof ApiError && err.sessionEnded) return ''
  // A server error is the one people report; its request id finds the
  // gateway's log lines, so it is shown with the message.
  if (err instanceof ApiError) return err.status >= 500 && err.requestId ? `${err.message} (reference ${err.requestId})` : err.message
  if (err instanceof Error) return err.message
  return String(err)
}
