import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SavedViews } from './SavedViews'

beforeEach(() => localStorage.clear())
afterEach(() => cleanup())

// 2026-11-03, idea 12: a reviewer names a filter and opens it again later,
// in this browser only.
describe('SavedViews', () => {
  it('saves the current filter under a name and opens it again', async () => {
    const user = userEvent.setup()
    const onOpen = vi.fn()
    const { rerender } = render(<SavedViews page="events" current="outcome=failure&range=7d" onOpen={onOpen} />)
    await user.click(screen.getByRole('button', { name: 'Save view' }))
    await user.type(screen.getByRole('textbox', { name: 'Name this view' }), 'Failures this week{Enter}')
    expect(JSON.parse(localStorage.getItem('zanskar.views.events')!)).toEqual([{ name: 'Failures this week', query: 'outcome=failure&range=7d' }])

    // Elsewhere, the view is a pick away; picking it opens its filter.
    rerender(<SavedViews page="events" current="" onOpen={onOpen} />)
    await user.selectOptions(screen.getByRole('combobox', { name: 'Saved views' }), 'Failures this week')
    expect(onOpen).toHaveBeenCalledWith('outcome=failure&range=7d')
  })

  it('offers nothing to save with no filter, and forgets a view on request', async () => {
    localStorage.setItem('zanskar.views.sessions', JSON.stringify([{ name: 'Live', query: 'open=1' }]))
    const user = userEvent.setup()
    const { rerender } = render(<SavedViews page="sessions" current="" onOpen={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Save view' })).toBeNull()
    rerender(<SavedViews page="sessions" current="open=1" onOpen={() => {}} />)
    await user.click(screen.getByRole('button', { name: 'Forget the view Live' }))
    expect(JSON.parse(localStorage.getItem('zanskar.views.sessions')!)).toEqual([])
    expect(screen.queryByRole('combobox', { name: 'Saved views' })).toBeNull()
  })

  it('reads a damaged store as empty, never breaking the page', () => {
    localStorage.setItem('zanskar.views.events', '{not json')
    render(<SavedViews page="events" current="a=1" onOpen={() => {}} />)
    expect(screen.getByRole('button', { name: 'Save view' })).toBeDefined()
  })
})
