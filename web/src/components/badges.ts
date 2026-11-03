// The sidebar's counts (the Approvals badge) re-read when something that
// changes them happens on this page, not only on their once-a-minute poll
// (2026-10-30: a decided request stayed counted until a reload).

const event = 'zanskar:badges'

/** badgesChanged asks every nav badge on the page to read its count again. */
export function badgesChanged() {
  window.dispatchEvent(new Event(event))
}

/** onBadgesChanged calls fn on every badgesChanged; it returns the unsubscribe. */
export function onBadgesChanged(fn: () => void): () => void {
  window.addEventListener(event, fn)
  return () => window.removeEventListener(event, fn)
}

// A page that has just read what a badge counts hands the count over, so the
// badge does not read it a third time (2026-11-03 live audit, Q12: Approvals
// asked for the pending requests three times on each visit).
const countEvent = 'zanskar:badge-count'

/** shareBadgeCount tells the nav badge of the page at path its count. */
export function shareBadgeCount(path: string, n: number) {
  window.dispatchEvent(new CustomEvent(countEvent, { detail: { path, n } }))
}

/** onBadgeCount calls fn with each count shared for path; it returns the
 *  unsubscribe. */
export function onBadgeCount(path: string, fn: (n: number) => void): () => void {
  const listen = (e: Event) => {
    const d = (e as CustomEvent<{ path: string; n: number }>).detail
    if (d && d.path === path && Number.isFinite(d.n)) fn(d.n)
  }
  window.addEventListener(countEvent, listen)
  return () => window.removeEventListener(countEvent, listen)
}
