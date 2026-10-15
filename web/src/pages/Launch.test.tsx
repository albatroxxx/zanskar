import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { Launch } from './Launch'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const at = (search: string, go: (url: string) => void) =>
  render(
    <MemoryRouter initialEntries={['/launch' + search]}>
      <Launch go={go} />
    </MemoryRouter>,
  )

// An application host sends a browser here with its label and a state
// (ADR 0033); the page asks for the hand-off and sends the browser back,
// or explains a refusal in place, since the host itself cannot.
describe('Launch', () => {
  it('asks for the hand-off and sends the browser to the application', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ url: 'https://wiki.apps.example.com/_zanskar/enter?code=c&state=s&next=%2Fdash' } as never)
    const go = vi.fn()
    at('?app=wiki&state=s&next=%2Fdash', go)

    await waitFor(() => expect(go).toHaveBeenCalledWith('https://wiki.apps.example.com/_zanskar/enter?code=c&state=s&next=%2Fdash'))
    expect(post).toHaveBeenCalledWith('/me/applications/launch', { app: 'wiki', state: 's', next: '/dash' })
  })

  it('explains a refusal and offers the way back', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(403, { code: 'approval_required', message: 'access to this target requires an approved request' }, '403'))
    const go = vi.fn()
    at('?app=wiki&state=s', go)

    expect(await screen.findByText('wiki needs an approved request before you can open it.')).toBeDefined()
    expect(screen.getByRole('link', { name: 'Back to the access portal' }).getAttribute('href')).toBe('/')
    expect(go).not.toHaveBeenCalled()
  })

  it('says what it is for when opened by hand', () => {
    const post = vi.spyOn(api, 'post')
    at('', vi.fn())
    expect(screen.getByText(/this page is where its address sends you to sign in/)).toBeDefined()
    expect(post).not.toHaveBeenCalled()
  })
})
