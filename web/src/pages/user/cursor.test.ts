import { describe, expect, it } from 'vitest'
import { MAX_CURSOR, pointerAsCursor } from './cursor'

const canvas = (w: number, h: number) => Object.assign(document.createElement('canvas'), { width: w, height: h })

// 2026-11-01: the remote pointer as the browser's cursor, within what the
// browser takes; otherwise the browser's own cursor is hidden for the
// software one.
describe('pointerAsCursor', () => {
  it('takes an image up to the browsers\' limit, and none past it', () => {
    const calls: number[] = []
    const mouse = { setCursor: (c: HTMLCanvasElement) => { calls.push(c.width); return true } }
    const el = document.createElement('div')
    expect(pointerAsCursor(mouse, el, canvas(MAX_CURSOR, MAX_CURSOR), 0, 0)).toBe(true)
    expect(pointerAsCursor(mouse, el, canvas(MAX_CURSOR + 1, 16), 0, 0)).toBe(false)
    expect(pointerAsCursor(mouse, el, canvas(16, MAX_CURSOR + 1), 0, 0)).toBe(false)
    expect(calls).toEqual([MAX_CURSOR])
    expect(el.style.cursor).toBe('none')
  })

  it('passes the hotspot through', () => {
    let got: number[] = []
    const mouse = { setCursor: (_: HTMLCanvasElement, x: number, y: number) => { got = [x, y]; return true } }
    pointerAsCursor(mouse, document.createElement('div'), canvas(24, 24), 11, 3)
    expect(got).toEqual([11, 3])
  })
})
