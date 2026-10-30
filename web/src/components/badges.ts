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
