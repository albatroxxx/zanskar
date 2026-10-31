import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TimeZonePicker } from './TimeZonePicker'

afterEach(cleanup)

function Harness({ initial, onChange }: { initial: string; onChange: (z: string) => void }) {
  const [value, setValue] = useState(initial)
  return (
    <>
      <label htmlFor="tz">Time zone</label>
      <TimeZonePicker id="tz" value={value} onChange={(z) => { setValue(z); onChange(z) }} />
      <button type="button">elsewhere</button>
    </>
  )
}

const field = () => screen.getByLabelText('Time zone') as HTMLInputElement
const options = () => screen.queryAllByRole('option')

// 2026-10-31: the field was a <datalist>, which offered only what matched
// the text already in it (the saved zone), so the arrow showed nothing.
describe('Choosing a time zone', () => {
  it('reads the saved zone in words, and opens every zone whatever it holds', async () => {
    render(<Harness initial="Asia/Kolkata" onChange={() => {}} />)
    expect(field().value).toMatch(/^UTC\+05:30 · Kolkata \(Asia\)/)
    expect(field().getAttribute('aria-expanded')).toBe('false')
    await userEvent.setup().click(field())
    expect(field().getAttribute('aria-expanded')).toBe('true')
    expect(options().length).toBeGreaterThan(300)
    const chosen = options().filter((o) => o.getAttribute('aria-selected') === 'true')
    expect(chosen).toHaveLength(1)
    expect(chosen[0].textContent).toContain('Kolkata')
    // The highlighted row starts on the saved zone.
    expect(field().getAttribute('aria-activedescendant')).toBe(chosen[0].id)
  })

  it('searches as it is typed, older names too, and takes a zone with Enter', async () => {
    const onChange = vi.fn()
    render(<Harness initial="UTC" onChange={onChange} />)
    const user = userEvent.setup()
    await user.click(field())
    await user.type(field(), 'calcutta')
    expect(options().map((o) => o.textContent)).toEqual([expect.stringContaining('Kolkata')])
    await user.keyboard('{Enter}')
    expect(onChange).toHaveBeenCalledWith('Asia/Kolkata')
    expect(field().getAttribute('aria-expanded')).toBe('false')
    expect(field().value).toContain('Kolkata')
  })

  it('moves with the arrow keys and takes a zone with a click', async () => {
    const onChange = vi.fn()
    render(<Harness initial="UTC" onChange={onChange} />)
    const user = userEvent.setup()
    field().focus()
    await user.keyboard('{ArrowDown}')
    expect(field().getAttribute('aria-expanded')).toBe('true')
    await user.type(field(), 'europe')
    const first = options()[0]
    expect(field().getAttribute('aria-activedescendant')).toBe(first.id)
    await user.keyboard('{ArrowDown}')
    expect(field().getAttribute('aria-activedescendant')).toBe(options()[1].id)
    fireEvent.mouseDown(options()[2])
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(onChange.mock.calls[0][0]).toMatch(/^Europe\//)
  })

  it('closes on Escape or a click elsewhere with the choice unchanged, and says when nothing matches', async () => {
    const onChange = vi.fn()
    render(<Harness initial="UTC" onChange={onChange} />)
    const user = userEvent.setup()
    await user.click(field())
    await user.type(field(), 'atlantis')
    expect(options()).toHaveLength(0)
    expect(screen.getByText('No zone matches “atlantis”.')).toBeDefined()
    await user.keyboard('{Escape}')
    expect(field().getAttribute('aria-expanded')).toBe('false')
    expect(field().value).toMatch(/^UTC\+00:00 · UTC/)

    await user.click(screen.getByRole('button', { name: 'Show every time zone' }))
    expect(options().length).toBeGreaterThan(300)
    await user.click(screen.getByRole('button', { name: 'elsewhere' }))
    expect(field().getAttribute('aria-expanded')).toBe('false')
    expect(onChange).not.toHaveBeenCalled()
  })
})
