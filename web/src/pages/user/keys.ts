// Keyboard helpers for the desktop and terminal pages: which keystroke is a
// paste, which one leaves the session for its controls, and a queue that keeps
// key events in order when one of them must wait.

// X11 keysyms for the V key, unshifted and shifted (Guacamole sends keysyms),
// and for F6, which Shift does not change.
const KEYSYM_V = 0x76
const KEYSYM_SHIFTED_V = 0x56
const KEYSYM_F6 = 0xffc3

/** isPasteKey reports whether a keydown is the user's paste gesture: V with Ctrl or Cmd held. */
export function isPasteKey(keysym: number, held: { ctrl: boolean; meta: boolean }): boolean {
  return (keysym === KEYSYM_V || keysym === KEYSYM_SHIFTED_V) && (held.ctrl || held.meta)
}

// The keystroke that moves focus from a session to the bar's controls, so a
// keyboard-only person can reach Disconnect (review U2, WCAG 2.1.2). Bare F6
// belongs to the remote side: Chromium in an application session, Windows
// programs, mc and htop all use it. Ctrl+Alt with a function key switches the
// console on a Linux client, and a modifiers-only chord would carry Ctrl+Shift
// or Alt+Shift, Windows' keyboard-layout switch, so it is Ctrl+Shift+F6 exactly.
export const CONTROLS_KEY = 'Ctrl+Shift+F6'

type Held = { ctrl: boolean; shift: boolean; alt: boolean; meta: boolean }

function controlsHeld(held: Held): boolean {
  return held.ctrl && held.shift && !held.alt && !held.meta
}

/** isControlsKey reports whether a desktop keydown, as a keysym, is CONTROLS_KEY. */
export function isControlsKey(keysym: number, held: Held): boolean {
  return keysym === KEYSYM_F6 && controlsHeld(held)
}

/** isControlsEvent reports whether a browser key event is CONTROLS_KEY being pressed. */
export function isControlsEvent(e: KeyboardEvent): boolean {
  return e.type === 'keydown' && e.key === 'F6' && controlsHeld({ ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey })
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
