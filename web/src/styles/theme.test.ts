import { afterEach, describe, expect, it, vi } from 'vitest'
import { applyTheme, consoleTheme, ownTheme, setConsoleTheme, shownTheme, themeEvent, themeKey, toggleTheme } from './theme'
import tokens from './tokens.css?raw'
import preload from '../../public/theme.js?raw'

const root = document.documentElement

/** device makes the operating system's theme dark or light; jsdom has none. */
function device(dark: boolean) {
  vi.stubGlobal('matchMedia', (q: string) => ({ matches: dark && q === '(prefers-color-scheme: dark)', media: q, addEventListener() {}, removeEventListener() {} }))
}

/** preloadWith runs public/theme.js as the gateway serves it, with the theme
 *  set for everyone written over its marker (internal/server/theme.go). */
function preloadWith(theme: string) {
  new Function(preload.replace(`'system' /* zanskar:theme */`, `'${theme}' /* zanskar:theme */`))()
}

afterEach(() => {
  localStorage.removeItem(themeKey)
  root.removeAttribute('data-theme')
  root.removeAttribute('data-theme-default')
  document.head.querySelectorAll('meta').forEach((m) => m.remove())
  vi.unstubAllGlobals()
})

/** props reads the custom properties of the block that opens at marker. */
function props(css: string, marker: string): Record<string, string> {
  const at = css.indexOf(marker)
  const body = css.slice(at + marker.length, css.indexOf('}', at))
  const out: Record<string, string> = {}
  for (const m of body.matchAll(/(--[\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim()
  return out
}

describe('theme tokens', () => {
  it('keeps the chosen dark tokens identical to the system dark tokens', () => {
    const system = props(tokens, ':root:not([data-theme="light"]) {')
    const chosen = props(tokens, ':root[data-theme="dark"] {')
    expect(Object.keys(system).length).toBeGreaterThan(20)
    expect(chosen).toEqual(system)
  })
})

// 2026-11-01: a theme for everyone in Settings, and the corner's menu of
// three became a switch between light and dark.
describe('the theme before paint', () => {
  it('draws the theme set for everyone, from a file the CSP allows', () => {
    preloadWith('dark')
    expect(root.getAttribute('data-theme-default')).toBe('dark')
    expect(root.getAttribute('data-theme')).toBe('dark')
    expect(consoleTheme()).toBe('dark')
  })

  it("puts this browser's own pick first", () => {
    localStorage.setItem(themeKey, 'light')
    preloadWith('dark')
    expect(root.getAttribute('data-theme')).toBe('light')
  })

  it('leaves the device to choose when everyone is on system, and ignores a stored value it does not know', () => {
    localStorage.setItem(themeKey, '"><img src=x>')
    new Function(preload)()
    expect(root.getAttribute('data-theme-default')).toBe('system')
    expect(root.hasAttribute('data-theme')).toBe(false)
    expect(ownTheme()).toBeNull()
  })
})

describe('the corner switch', () => {
  it('switches to the other theme, and forgets the pick when it is back on the theme for everyone', () => {
    preloadWith('dark')
    expect(shownTheme()).toBe('dark')
    expect(toggleTheme()).toBe('light')
    expect(root.getAttribute('data-theme')).toBe('light')
    expect(localStorage.getItem(themeKey)).toBe('light')
    expect(toggleTheme()).toBe('dark')
    expect(root.getAttribute('data-theme')).toBe('dark')
    expect(localStorage.getItem(themeKey)).toBeNull()
  })

  it('on system, matches the device at the click and then follows the device again', () => {
    device(true)
    preloadWith('system')
    expect(shownTheme()).toBe('dark')
    expect(toggleTheme()).toBe('light')
    expect(localStorage.getItem(themeKey)).toBe('light')
    expect(root.getAttribute('data-theme')).toBe('light')
    expect(toggleTheme()).toBe('dark')
    expect(localStorage.getItem(themeKey)).toBeNull()
    expect(root.hasAttribute('data-theme')).toBe(false)
    device(false)
    expect(shownTheme()).toBe('light')
  })

  it('points the browser chrome at the theme and tells the page', () => {
    document.head.insertAdjacentHTML('beforeend', '<meta name="color-scheme" content="light dark"><meta name="theme-color" media="(prefers-color-scheme: light)" content="#f4f2ec">')
    const told = vi.fn()
    window.addEventListener(themeEvent, told)
    toggleTheme()
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute('content')).toBe('dark')
    toggleTheme()
    window.removeEventListener(themeEvent, told)
    expect(told).toHaveBeenCalledTimes(2)
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute('content')).toBe('light dark')
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content')).toBe('#f4f2ec')
  })
})

describe('a new theme for everyone, saved in Settings', () => {
  it("is drawn here at once, and this browser's own pick is forgotten", () => {
    preloadWith('system')
    localStorage.setItem(themeKey, 'dark')
    applyTheme()
    expect(root.getAttribute('data-theme')).toBe('dark')
    setConsoleTheme('light')
    expect(root.getAttribute('data-theme-default')).toBe('light')
    expect(root.getAttribute('data-theme')).toBe('light')
    expect(localStorage.getItem(themeKey)).toBeNull()
    setConsoleTheme('neon')
    expect(consoleTheme()).toBe('system')
    expect(root.hasAttribute('data-theme')).toBe(false)
  })
})
