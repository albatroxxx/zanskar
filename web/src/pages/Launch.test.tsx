import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Launch } from './Launch'

afterEach(cleanup)

const at = (search: string, go: (a: HTMLAnchorElement) => void) =>
  render(
    <MemoryRouter initialEntries={['/launch' + search]}>
      <Launch go={go} />
    </MemoryRouter>,
  )

// An application host sends a browser here with its label and a state
// (ADR 0033); the page follows one link to the gateway's own route, which
// sends the browser on, and explains a refusal the gateway sent back, since
// the host itself cannot.
describe('Launch', () => {
  it('follows the gateway link carrying the label, state and return path', async () => {
    const go = vi.fn()
    at('?app=wiki&state=s&next=%2Fdash%3Fx%3D1', go)

    await waitFor(() => expect(go).toHaveBeenCalledTimes(1))
    const link = go.mock.calls[0][0] as HTMLAnchorElement
    expect(link.getAttribute('href')).toBe('/api/v1/me/applications/launch?app=wiki&state=s&next=%2Fdash%3Fx%3D1')
    // The link stays on the page for a browser that did not follow it.
    expect(screen.getByRole('link', { name: 'Open wiki' })).toBe(link)
    expect(screen.getByText('Opening wiki…')).toBeDefined()
  })

  it('explains a refusal and offers the way back', () => {
    const go = vi.fn()
    at('?app=wiki&error=approval_required', go)

    expect(screen.getByText('wiki needs an approved request before you can open it; ask for one under Targets.')).toBeDefined()
    expect(screen.getByRole('link', { name: 'Back to the access portal' }).getAttribute('href')).toBe('/')
    expect(go).not.toHaveBeenCalled()
  })

  it('says what it is for when opened by hand', () => {
    const go = vi.fn()
    at('', go)
    expect(screen.getByText(/this page is where its address sends you to sign in/)).toBeDefined()
    expect(go).not.toHaveBeenCalled()
  })
})
