import { describe, expect, it } from 'vitest'

const styles = import.meta.glob<string>('./*.css', { query: '?raw', import: 'default', eager: true })
const sources = import.meta.glob<string>('../**/*.tsx', { query: '?raw', import: 'default', eager: true })

// 2026-10-30: the single sign-on button on the sign-in page underlined on
// hover, from the global a:hover rule. The console underlines nothing: a
// plain link deepens its colour, a link dressed as a button keeps the
// button's hover.
describe('links', () => {
  it('never underline, in a stylesheet or inline', () => {
    for (const [path, css] of Object.entries(styles)) {
      expect(css, path).not.toMatch(/text-decoration(-line)?\s*:\s*[^;]*underline/)
    }
    for (const [path, src] of Object.entries(sources)) {
      if (path.includes('.test.')) continue
      expect(src, path).not.toMatch(/textDecoration\s*:\s*['"][^'"]*underline/)
    }
  })

  it('leave a link dressed as something else to its own hover', () => {
    const css = styles['./base.css']
    expect(css).toMatch(/a:where\(:not\(\[class\]\)\):hover\s*\{/)
    expect(css).not.toMatch(/(^|\n)a:hover\s*\{/)
  })
})
