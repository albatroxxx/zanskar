import { afterEach, describe, expect, it } from 'vitest'
import { terminalTheme } from './theme'

// Every stylesheet and source file, as text. Tests and this folder's
// tokens.css are left out below: tokens.css is where colours are written.
const styles = import.meta.glob<string>('./*.css', { query: '?raw', import: 'default', eager: true })
const sources = import.meta.glob<string>('../**/*.{ts,tsx}', { query: '?raw', import: 'default', eager: true })

/** stripComments drops CSS and JS comments, so an issue number such as #205
 *  in a comment is not read as a colour. Line breaks stay, so a reported
 *  line number is the file's. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, '')).replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const cssColour = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?)\(/i
// In code a colour is a string: '#fff', or rgb(...) inside one.
const codeColour = /['"`]#[0-9a-f]{3,8}['"`]|\b(?:rgba?|hsla?)\(/i

/** tokenBlock returns the custom properties declared in one block of tokens.css. */
function tokenBlock(css: string, dark: boolean): Record<string, string> {
  const at = css.indexOf('@media (prefers-color-scheme: dark)')
  const block = dark ? css.slice(at) : css.slice(0, at)
  const out: Record<string, string> = {}
  for (const m of stripComments(block).matchAll(/(--[\w-]+):\s*([^;]+);/g)) out[m[1]] = m[2].trim()
  return out
}

/** luminance is the WCAG relative luminance of a #rrggbb colour. */
function luminance(hex: string): number {
  const n = hex.replace('#', '')
  const [r, g, b] = [0, 2, 4].map((i) => {
    const c = parseInt(n.slice(i, i + 2), 16) / 255
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

afterEach(() => {
  document.documentElement.removeAttribute('style')
})

// Q7: colours written straight into the rules bypassed the tokens, so a theme
// change missed them. Every colour resolves to a token in tokens.css.
describe('colours', () => {
  it('are written only in tokens.css', () => {
    const offenders: string[] = []
    for (const [path, text] of Object.entries(styles)) {
      if (path.endsWith('/tokens.css')) continue
      stripComments(text).split('\n').forEach((line, i) => {
        if (cssColour.test(line)) offenders.push(`${path}:${i + 1}: ${line.trim()}`)
      })
    }
    for (const [path, text] of Object.entries(sources)) {
      // theme.ts repeats the terminal tokens as fallbacks for the moment
      // before the stylesheet loads; the next test checks it reads them.
      if (/\.test\.tsx?$/.test(path) || path.endsWith('/theme.ts')) continue
      stripComments(text).split('\n').forEach((line, i) => {
        if (codeColour.test(line)) offenders.push(`${path}:${i + 1}: ${line.trim()}`)
      })
    }
    expect(offenders).toEqual([])
  })

  // The filter boxes beside a page title each carried the same border,
  // padding and background inline; they take that look from one class.
  it('of a page filter box come from one class, not each page', () => {
    const inline = /style=\{\{[^}]*border: '1px solid var\(--line-strong\)'/
    const offenders = Object.entries(sources)
      .filter(([path]) => !/\.test\.tsx?$/.test(path))
      .flatMap(([path, text]) => text.split('\n').flatMap((line, i) => (inline.test(line) ? [`${path}:${i + 1}`] : [])))
    expect(offenders).toEqual([])
  })

  it('reach the terminal from the tokens', () => {
    const set = {
      '--terminal-bg': 'rgb(1, 2, 3)',
      '--term-fg': 'rgb(4, 5, 6)',
      '--term-link': 'rgb(7, 8, 9)',
      '--term-selection': 'rgba(10, 11, 12, 0.5)',
    }
    for (const [k, v] of Object.entries(set)) document.documentElement.style.setProperty(k, v)
    expect(terminalTheme()).toEqual({
      background: 'rgb(1, 2, 3)',
      foreground: 'rgb(4, 5, 6)',
      cursor: 'rgb(7, 8, 9)',
      cursorAccent: 'rgb(1, 2, 3)',
      selectionBackground: 'rgba(10, 11, 12, 0.5)',
    })
  })
})

// B29: in dark mode the accent is a light periwinkle, and white text on it
// measured 2.49:1. Text on an accent fill is --accent-fg, which each theme
// picks to contrast with its own accent.
describe('text on the accent', () => {
  it('uses --accent-fg wherever the accent is a fill', () => {
    const base = Object.entries(styles).find(([p]) => p.endsWith('/base.css'))![1]
    const wrong = stripComments(base)
      .split('}')
      .filter((rule) => /background:\s*var\(--accent\)\s*[;}]?/.test(rule + ';') && /[{;]\s*color:/.test(rule))
      .filter((rule) => !/[{;]\s*color:\s*var\(--accent-fg\)/.test(rule))
      .map((rule) => rule.trim().split('{')[0].trim())
    expect(wrong).toEqual([])
  })

  it('reads at 4.5:1 or better in both themes', () => {
    const tokens = Object.entries(styles).find(([p]) => p.endsWith('/tokens.css'))![1]
    const light = tokenBlock(tokens, false)
    const dark = { ...light, ...tokenBlock(tokens, true) }
    const resolve = (t: Record<string, string>, v: string): string => (v.startsWith('var(') ? resolve(t, t[v.slice(4, -1)]) : v)
    for (const t of [light, dark]) {
      expect(contrast(resolve(t, t['--accent']), resolve(t, t['--accent-fg']))).toBeGreaterThanOrEqual(4.5)
    }
  })
})
