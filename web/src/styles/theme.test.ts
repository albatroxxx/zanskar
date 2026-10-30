import { afterEach, describe, expect, it } from 'vitest'
import { readTheme, setTheme, themeKey } from './theme'
import tokens from './tokens.css?raw'
import preload from '../../public/theme.js?raw'

afterEach(() => {
  setTheme('system')
  document.head.querySelectorAll('meta').forEach((m) => m.remove())
})

/** props reads the custom properties of the block that opens at marker. */
function props(css: string, marker: string): Record<string, string> {
  const at = css.indexOf(marker)
  const body = css.slice(at + marker.length, css.indexOf('}', at))
  const out: Record<string, string> = {}
  for (const m of body.matchAll(/(--[\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim()
  return out
}

// 2026-10-30: the theme followed the operating system only; the corner menu
// picks System, Light or Dark.
describe('theme choice', () => {
  it('keeps the chosen dark tokens identical to the system dark tokens', () => {
    const system = props(tokens, ':root:not([data-theme="light"]) {')
    const chosen = props(tokens, ':root[data-theme="dark"] {')
    expect(Object.keys(system).length).toBeGreaterThan(20)
    expect(chosen).toEqual(system)
  })

  it('applies and keeps a choice, and system forgets it', () => {
    document.head.insertAdjacentHTML('beforeend', '<meta name="color-scheme" content="light dark"><meta name="theme-color" media="(prefers-color-scheme: light)" content="#f4f2ec">')
    expect(readTheme()).toBe('system')
    setTheme('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(localStorage.getItem(themeKey)).toBe('dark')
    expect(readTheme()).toBe('dark')
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute('content')).toBe('dark')
    setTheme('system')
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
    expect(localStorage.getItem(themeKey)).toBeNull()
    expect(document.querySelector('meta[name="color-scheme"]')?.getAttribute('content')).toBe('light dark')
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content')).toBe('#f4f2ec')
  })

  it('ignores a stored value it does not know', () => {
    localStorage.setItem(themeKey, 'neon')
    expect(readTheme()).toBe('system')
    localStorage.removeItem(themeKey)
  })

  it('applies the stored choice before paint, from a file the CSP allows', () => {
    localStorage.setItem(themeKey, 'light')
    new Function(preload)()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    localStorage.setItem(themeKey, '"><img src=x>')
    document.documentElement.removeAttribute('data-theme')
    new Function(preload)()
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
    localStorage.removeItem(themeKey)
  })
})
