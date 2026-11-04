import { cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { PageHead } from './ui'

beforeEach(() => {
  document.title = 'Zanskar'
})
afterEach(cleanup)

// 2026-11-04, live walkthrough of 1.18.4: every page's tab, and every entry
// in the browser's history, read just "Zanskar".
describe('PageHead names the tab', () => {
  it('after the page, and gives the plain title back when the page goes', () => {
    const { unmount } = render(<PageHead title="Users & groups" />)
    expect(document.title).toBe('Users & groups · Zanskar')
    unmount()
    expect(document.title).toBe('Zanskar')
  })

  it('follows a page whose title changes, and a later page replaces an earlier one', () => {
    const { rerender, unmount } = render(<PageHead title="Hosts" />)
    expect(document.title).toBe('Hosts · Zanskar')
    rerender(<PageHead title="Applications" />)
    expect(document.title).toBe('Applications · Zanskar')
    unmount()
    render(<PageHead title="Policies" />)
    expect(document.title).toBe('Policies · Zanskar')
  })
})
