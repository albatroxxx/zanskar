import { describe, expect, it } from 'vitest'
import { browserKeys, isPasteKey, keyQueue, pressCombo } from './keys'

describe('desktop keys', () => {
  it('knows the paste gesture', () => {
    expect(isPasteKey(0x76, { ctrl: true, meta: false })).toBe(true)
    expect(isPasteKey(0x56, { ctrl: false, meta: true })).toBe(true)
    expect(isPasteKey(0x76, { ctrl: false, meta: false })).toBe(false)
    expect(isPasteKey(0x63, { ctrl: true, meta: false })).toBe(false) // Ctrl+C
  })

  it('pastes before the key reaches the desktop, and keeps later keys behind it', async () => {
    const log: string[] = []
    let release: () => void = () => {}
    const clipboard = () => new Promise<void>((r) => { release = () => { log.push('clipboard sent'); r() } })
    const enqueue = keyQueue((pressed, k) => log.push(`${pressed ? 'down' : 'up'} ${k.toString(16)}`))
    void enqueue(1, 0x76, clipboard) // Ctrl+V pressed
    const last = enqueue(0, 0x76) // released before the clipboard read finished
    await Promise.resolve()
    expect(log).toEqual([])
    release()
    await last
    expect(log).toEqual(['clipboard sent', 'down 76', 'up 76'])
  })

  it('lets the key through when reading the clipboard fails', async () => {
    const log: string[] = []
    const enqueue = keyQueue((pressed, k) => log.push(`${pressed} ${k}`))
    await enqueue(1, 0x76, () => Promise.reject(new Error('denied')))
    expect(log).toEqual(['1 118'])
  })
})

// 2026-10-30 walkthrough: an application's browser has no controls, so a page
// the policy blocked was a dead end. The desktop bar sends the browser's own
// shortcuts.
describe('pressCombo', () => {
  it('presses in order and releases in reverse', () => {
    const sent: [number, number][] = []
    pressCombo((p, k) => sent.push([p, k]), browserKeys.back)
    expect(sent).toEqual([[1, 0xffe9], [1, 0xff51], [0, 0xff51], [0, 0xffe9]])
  })

  it('names the browser shortcuts', () => {
    expect(browserKeys.forward).toEqual([0xffe9, 0xff53])
    expect(browserKeys.reload).toEqual([0xffc2])
    expect(browserKeys.home).toEqual([0xffe9, 0xff50])
  })
})
