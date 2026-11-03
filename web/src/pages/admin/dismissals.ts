// A dashboard notice an administrator closed stays closed when they come back
// to the dashboard (2026-11-03: the provider notice came back on every visit).
// The dismissal is this browser's, kept in localStorage: it lasts while the
// condition lasts, is forgotten once the condition clears (so the next outage
// shows again), and lapses after REMIND_MS, so an outage left for a day is
// said again rather than forgotten. It holds the count the notice gave when it
// was closed: more failing than that is news, and the notice shows again.

/** How long a dismissal holds while the condition goes on. */
export const REMIND_MS = 24 * 60 * 60_000

const prefix = 'zanskar.dismissed.'

/** A notice closed at `at` while it counted `count`. */
export type Dismissal = { at: number; count: number }

/** dismissal is when, and at what count, the notice was closed in this
 *  browser; null when it was not, or what is kept cannot be read. */
export function dismissal(key: string): Dismissal | null {
  try {
    const [at, count] = (localStorage.getItem(prefix + key) ?? '').split('/').map(Number)
    return at > 0 && count > 0 && Number.isSafeInteger(at) && Number.isSafeInteger(count) ? { at, count } : null
  } catch {
    return null
  }
}

/** dismiss remembers the notice closed. */
export function dismiss(key: string, d: Dismissal): void {
  try {
    localStorage.setItem(prefix + key, `${d.at}/${d.count}`)
  } catch {
    // A browser that keeps nothing closes the notice for this visit only.
  }
}

/** forget drops the dismissal: the condition has cleared. */
export function forget(key: string): void {
  try {
    localStorage.removeItem(prefix + key)
  } catch {
    // nothing kept, nothing to drop
  }
}

/** shown says whether a notice that now counts `count` is shown at `now`:
 *  never closed, closed at a lower count, or closed more than REMIND_MS ago. */
export function shown(d: Dismissal | null, count: number, now: number): boolean {
  return d === null || count > d.count || now - d.at >= REMIND_MS
}
