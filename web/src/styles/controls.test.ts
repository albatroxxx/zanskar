import { describe, expect, it } from 'vitest'

const styles = import.meta.glob<string>('./*.css', { query: '?raw', import: 'default', eager: true })

// 2026-11-03: the role checks in Users & groups were the browser's own blue,
// off the console's palette. Checkboxes and radios take the accent token,
// which follows the theme.
describe('form controls', () => {
  it('draw checkboxes and radios in the accent', () => {
    const css = styles['./base.css']
    expect(css).toMatch(/input\[type="checkbox"\],\s*input\[type="radio"\]\s*\{\s*accent-color:\s*var\(--accent\);\s*\}/)
  })

  it('name no colour of their own for a checkbox anywhere else', () => {
    for (const [path, css] of Object.entries(styles)) {
      const own = css.match(/accent-color:\s*([^;]+);/g) ?? []
      for (const decl of own) expect(decl, path).toMatch(/var\(--accent\)/)
    }
  })
})
