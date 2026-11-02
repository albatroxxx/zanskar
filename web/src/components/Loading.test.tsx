import { render, screen } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { Loading } from './ui'

// 2026-11-03 live audit, Q11: a fast first load flashed "Loading…" before the
// page. The text stays for a slow load, but is held back for 400 ms.
describe('Loading', () => {
  it('says Loading… and is held back until a load is slow', () => {
    render(<Loading />)
    const el = screen.getByText('Loading…')
    expect(el.className).toContain('pending')
    const css = readFileSync('src/styles/base.css', 'utf8')
    expect(css).toMatch(/\.empty\.pending \{ opacity: 0; animation: reveal-pending 0s linear 400ms forwards; \}/)
  })
})
