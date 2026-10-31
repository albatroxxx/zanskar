import { describe, expect, it } from 'vitest'
import { isPasteKey, keyQueue } from './keys'

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
