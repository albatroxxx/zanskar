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

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken
  const res = await fetch('/api/v1' + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let parsed: unknown = null
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = null
    }
  }
  if (!res.ok) {
    // A 401 from /auth is a failed sign-in or the unauthenticated probe on
    // startup, both of which the login page reports itself. Anywhere else it
    // means the session this page was relying on has gone.
    const err = new ApiError(res.status, parsed as ApiErrorBody | null, `${res.status} ${res.statusText}`)
    if (res.status === 401 && !path.startsWith('/auth/')) {
      err.sessionEnded = true
      onSessionEnded?.()
    }
    throw err
  }
  return parsed as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
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

export function errorMessage(err: unknown): string {
  // An expired session is announced once, by the session dialog. Repeating it
  // as an error banner inside the page would only be noise behind that dialog.
  if (err instanceof ApiError && err.sessionEnded) return ''
  if (err instanceof ApiError) return err.message
  if (err instanceof Error) return err.message
  return String(err)
}
