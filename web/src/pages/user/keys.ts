// Keyboard helpers for the desktop page: which keystroke is a paste, and a
// queue that keeps key events in order when one of them must wait.

// X11 keysyms for the V key, unshifted and shifted (Guacamole sends keysyms).
const KEYSYM_V = 0x76
const KEYSYM_SHIFTED_V = 0x56

/** isPasteKey reports whether a keydown is the user's paste gesture: V with Ctrl or Cmd held. */
export function isPasteKey(keysym: number, held: { ctrl: boolean; meta: boolean }): boolean {
  return (keysym === KEYSYM_V || keysym === KEYSYM_SHIFTED_V) && (held.ctrl || held.meta)
}

/**
 * keyQueue sends key events in the order they happened. An event may first
 * run `before` (reading the clipboard for a paste); the events after it wait
 * their turn rather than overtaking it, and a failed `before` still lets the
 * key through.
 */
export function keyQueue(send: (pressed: 0 | 1, keysym: number) => void) {
  let chain: Promise<void> = Promise.resolve()
  return (pressed: 0 | 1, keysym: number, before?: () => Promise<void>): Promise<void> => {
    const key = () => send(pressed, keysym)
    chain = chain.then(before ?? (() => undefined)).then(key, key)
    return chain
  }
}

// The isolated browser (ADR 0034) runs Chromium in kiosk mode: no address
// bar, no buttons. Its own shortcuts move it, sent as keystrokes like any
// other: Alt+Left back, Alt+Right forward, F5 reload, Alt+Home to the home
// page, which the image's policy sets to the application's start page.
const ALT = 0xffe9
export const browserKeys = {
  back: [ALT, 0xff51],
  forward: [ALT, 0xff53],
  reload: [0xffc2],
  home: [ALT, 0xff50],
} as const

/** pressCombo presses keys in order and releases them in reverse, through send. */
export function pressCombo(send: (pressed: 0 | 1, keysym: number) => unknown, keys: readonly number[]) {
  for (const k of keys) send(1, k)
  for (const k of [...keys].reverse()) send(0, k)
}
