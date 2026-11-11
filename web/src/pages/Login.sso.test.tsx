import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { Login } from './Login'

vi.mock('qrcode', () => ({ default: { toDataURL: async () => 'data:image/png;base64,AA==' } }))

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  window.history.replaceState(null, '', '/')
})

// 2026-11-03 live audit, idea 1: a provider the gateway cannot reach is said
// before anyone presses its button and waits. 2026-11-11 (owner): its button
// is greyed out, the reason is in a tip on hover, focus or a tap, and a check
// beside it reads the list again.

type Item = { id: string; name: string; type: string; not_answering?: boolean }

// signIn renders the page; each read of the provider list takes the next
// answer, the last one repeating, and an Error answer fails the read.
function signIn(...lists: (Item[] | Error)[]) {
  let read = 0
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
    if (path === '/auth/providers') {
      const answer = lists[Math.min(read++, lists.length - 1)]
      if (answer instanceof Error) throw answer
      return { items: answer } as never
    }
    return { text: '' } as never
  })
  render(
    <MemoryRouter>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>,
  )
}

const down: Item = { id: 'kc', name: 'Keycloak', type: 'oidc', not_answering: true }
const up: Item = { id: 'kc', name: 'Keycloak', type: 'oidc' }
const note = 'Keycloak is not answering.'

describe('a single sign-on provider', () => {
  it('that is not answering is greyed out, with the reason in a tip and no way to start', async () => {
    signIn([down, { id: 'ak', name: 'Authentik', type: 'oidc' }])
    const button = await screen.findByRole('button', { name: 'Continue with Keycloak' })
    expect(button.getAttribute('aria-disabled')).toBe('true')
    expect(button.getAttribute('href')).toBeNull()
    expect(screen.queryByRole('link', { name: 'Continue with Keycloak' })).toBeNull()
    const tip = screen.getByRole('tooltip', { hidden: true })
    expect(tip.textContent).toBe(note)
    expect(button.getAttribute('aria-describedby')).toBe(tip.id)
    expect(tip.className).not.toContain('open')
    // The other provider is untouched.
    const other = screen.getByRole('link', { name: 'Continue with Authentik' })
    expect(other.getAttribute('href')).toContain('/api/v1/auth/oidc/ak/start')
    expect(other.getAttribute('aria-describedby')).toBeNull()
  })

  it('shows its tip on hover and on focus, and Esc closes it', async () => {
    signIn([down])
    const button = await screen.findByRole('button', { name: 'Continue with Keycloak' })
    const tip = screen.getByRole('tooltip', { hidden: true })
    fireEvent.pointerEnter(button.parentElement!, { pointerType: 'mouse' })
    expect(tip.className).toContain('open')
    fireEvent.pointerLeave(button.parentElement!, { pointerType: 'mouse' })
    expect(tip.className).not.toContain('open')
    fireEvent.focus(button)
    expect(tip.className).toContain('open')
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(tip.className).not.toContain('open')
  })

  it('shows its tip on a tap, which starts nothing', async () => {
    signIn([down])
    const button = await screen.findByRole('button', { name: 'Continue with Keycloak' })
    // A touch fires no hover of its own.
    fireEvent.pointerEnter(button.parentElement!, { pointerType: 'touch' })
    expect(screen.getByRole('tooltip', { hidden: true }).className).not.toContain('open')
    fireEvent.click(button)
    expect(screen.getByRole('tooltip', { hidden: true }).className).toContain('open')
    expect(window.location.pathname).toBe('/')
  })

  it('that answers again after a check becomes the button, takes focus, and clears the failed sign-in note', async () => {
    window.history.replaceState(null, '', '/login?error=provider_unavailable')
    signIn([down], [up])
    expect(await screen.findByText(/Single sign-on is not answering\./)).toBeTruthy()
    const check = await screen.findByRole('button', { name: 'Check Keycloak again' })
    await act(async () => {
      fireEvent.click(check)
    })
    const link = await screen.findByRole('link', { name: 'Continue with Keycloak' })
    expect(link.getAttribute('href')).toContain('/api/v1/auth/oidc/kc/start')
    expect(document.activeElement).toBe(link)
    expect(screen.queryByRole('button', { name: 'Check Keycloak again' })).toBeNull()
    expect(screen.getByRole('status').textContent).toBe('Keycloak is answering again.')
    expect(screen.queryByText(/Single sign-on is not answering\./)).toBeNull()
  })

  it('that is still not answering after a check stays greyed out and says so', async () => {
    signIn([down], [down])
    const check = await screen.findByRole('button', { name: 'Check Keycloak again' })
    await act(async () => {
      fireEvent.click(check)
    })
    expect(screen.getByRole('status').textContent).toBe('Keycloak is still not answering.')
    expect(screen.getByRole('button', { name: 'Continue with Keycloak' }).getAttribute('aria-disabled')).toBe('true')
    expect(screen.getByRole('tooltip', { hidden: true }).className).toContain('open')
    expect(check.getAttribute('aria-busy')).toBe('false')
  })

  it('keeps what it showed when the check cannot read the list', async () => {
    signIn([down], new Error('offline'))
    const check = await screen.findByRole('button', { name: 'Check Keycloak again' })
    await act(async () => {
      fireEvent.click(check)
    })
    expect(screen.getByRole('status').textContent).toBe('Could not check. Try again.')
    expect(screen.getByRole('button', { name: 'Continue with Keycloak' }).getAttribute('aria-disabled')).toBe('true')
  })

  it('reads the list once for a check pressed twice', async () => {
    let release: () => void = () => {}
    signIn([down])
    const check = await screen.findByRole('button', { name: 'Check Keycloak again' })
    const get = vi.mocked(api.get)
    const before = get.mock.calls.filter(([p]) => p === '/auth/providers').length
    get.mockImplementation(async (path: string) => {
      if (path === '/auth/providers') {
        await new Promise<void>((r) => (release = r))
        return { items: [up] } as never
      }
      return { text: '' } as never
    })
    fireEvent.click(check)
    fireEvent.click(check)
    expect(check.getAttribute('aria-busy')).toBe('true')
    await act(async () => release())
    expect(get.mock.calls.filter(([p]) => p === '/auth/providers').length).toBe(before + 1)
    expect(await screen.findByRole('link', { name: 'Continue with Keycloak' })).toBeTruthy()
  })

  it('that answers carries no tip and no check', async () => {
    signIn([up])
    await screen.findByRole('link', { name: 'Continue with Keycloak' })
    expect(screen.queryByRole('tooltip', { hidden: true })).toBeNull()
    expect(screen.queryByRole('button', { name: /Check .* again/ })).toBeNull()
    expect(screen.queryByText(/not answering/)).toBeNull()
  })
})

describe('the username', () => {
  it('is not capitalised or spell-checked by a phone keyboard', async () => {
    signIn([])
    const input = await screen.findByLabelText('Username')
    expect(input.getAttribute('autocapitalize')).toBe('none')
    expect(input.getAttribute('spellcheck')).toBe('false')
  })
})
