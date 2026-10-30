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

/** The theme an administrator picked in the corner menu; system follows the OS. */
export type ThemeChoice = 'system' | 'light' | 'dark'

/** themeKey is where the choice is kept, per browser; public/theme.js reads it before paint. */
export const themeKey = 'zanskar.theme'

/** readTheme is the stored choice, system when there is none or storage is blocked. */
export function readTheme(): ThemeChoice {
  try {
    const t = localStorage.getItem(themeKey)
    return t === 'light' || t === 'dark' ? t : 'system'
  } catch {
    return 'system'
  }
}

/**
 * setTheme applies a choice at once and keeps it: data-theme on the root
 * picks the token block in tokens.css, and the browser chrome (theme-color,
 * color-scheme) follows the page's own background.
 */
export function setTheme(t: ThemeChoice) {
  const root = document.documentElement
  if (t === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', t)
  try {
    if (t === 'system') localStorage.removeItem(themeKey)
    else localStorage.setItem(themeKey, t)
  } catch {
    // Storage blocked: the choice lasts for this page only.
  }
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
}
