/** terminalTheme reads the always-dark terminal tokens from the stylesheet so
 *  xterm's canvas matches the page chrome around it. One source of truth for
 *  the colours lives in tokens.css; the fallbacks only matter before CSS loads. */
export function terminalTheme() {
  const s = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => s.getPropertyValue(name).trim() || fallback
  return {
    background: v('--terminal-bg', '#181a1f'),
    foreground: v('--term-fg', '#e8e4da'),
    cursor: v('--term-link', '#a9b4ff'),
    cursorAccent: v('--terminal-bg', '#181a1f'),
    selectionBackground: v('--term-selection', 'rgba(169, 180, 255, 0.28)'),
  }
}

/** A theme the console can be drawn in; system follows the operating system. */
export type ThemeChoice = 'system' | 'light' | 'dark'

/** The two themes a page is actually drawn in. */
export type Shown = 'light' | 'dark'

/** themeKey is where this browser's own pick is kept; public/theme.js reads it before paint. */
export const themeKey = 'zanskar.theme'

/** themeEvent goes to window whenever the theme drawn may have changed. */
export const themeEvent = 'zanskar:theme'

function isChoice(t: unknown): t is ThemeChoice {
  return t === 'system' || t === 'light' || t === 'dark'
}

/** consoleTheme is the theme an administrator set for everyone in Settings
 *  (display.theme), as public/theme.js wrote it on the root before paint. */
export function consoleTheme(): ThemeChoice {
  const t = document.documentElement.getAttribute('data-theme-default')
  return isChoice(t) ? t : 'system'
}

/** ownTheme is this browser's pick from the corner switch, or null when it
 *  follows the console's theme (or storage is blocked). */
export function ownTheme(): Shown | null {
  try {
    const t = localStorage.getItem(themeKey)
    return t === 'light' || t === 'dark' ? t : null
  } catch {
    return null
  }
}

function deviceTheme(): Shown {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function drawn(t: ThemeChoice): Shown {
  return t === 'system' ? deviceTheme() : t
}

/** shownTheme is the theme the page is drawn in now. */
export function shownTheme(): Shown {
  return drawn(ownTheme() ?? consoleTheme())
}

/**
 * toggleTheme switches this browser to the other theme and returns it. The
 * pick is kept only while it differs from what the console's theme draws:
 * switching back to that forgets it, and the browser follows the console's
 * theme again. With the console's theme on system, that is matched against
 * the device at the click, and from then on the device is followed, even if
 * it changes.
 */
export function toggleTheme(): Shown {
  const next: Shown = shownTheme() === 'dark' ? 'light' : 'dark'
  const own = next === drawn(consoleTheme()) ? null : next
  keep(own)
  draw(own ?? consoleTheme())
  return next
}

/** setConsoleTheme takes a new theme for everyone, just saved in Settings.
 *  This browser follows it at once and forgets its own pick, so the person
 *  who chose it sees it (an older pick would otherwise hide the change). */
export function setConsoleTheme(t: string) {
  const choice = isChoice(t) ? t : 'system'
  document.documentElement.setAttribute('data-theme-default', choice)
  keep(null)
  draw(choice)
}

/** applyTheme draws the page in what this browser shows now. public/theme.js
 *  chose the token block before paint; this also points the browser chrome
 *  (theme-color, color-scheme) at it. */
export function applyTheme() {
  draw(ownTheme() ?? consoleTheme())
}

function keep(t: Shown | null) {
  try {
    if (t) localStorage.setItem(themeKey, t)
    else localStorage.removeItem(themeKey)
  } catch {
    // Storage blocked: the pick lasts for this page only.
  }
}

/**
 * draw applies a choice: data-theme on the root picks the token block in
 * tokens.css, and the browser chrome (theme-color, color-scheme) follows the
 * page's own background.
 */
function draw(t: ThemeChoice) {
  const root = document.documentElement
  if (t === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', t)
  const scheme = document.querySelector('meta[name="color-scheme"]')
  scheme?.setAttribute('content', t === 'system' ? 'light dark' : t)
  // index.html sets a light and a dark theme-color; an explicit choice
  // points both at the page's background, and system puts them back.
  const bg = getComputedStyle(root).getPropertyValue('--bg').trim()
  for (const m of Array.from(document.querySelectorAll('meta[name="theme-color"]'))) {
    if (!m.hasAttribute('data-default')) m.setAttribute('data-default', m.getAttribute('content') ?? '')
    const content = t === 'system' || !bg ? m.getAttribute('data-default') : bg
    if (content) m.setAttribute('content', content)
  }
  window.dispatchEvent(new Event(themeEvent))
}
