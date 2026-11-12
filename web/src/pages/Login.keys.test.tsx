import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { Login } from './Login'

vi.mock('qrcode', () => ({ default: { toDataURL: async () => 'data:image/png;base64,AA==' } }))

const buf = (...b: number[]) => new Uint8Array(b).buffer
const answer = {
  id: 'AQI', rawId: buf(1, 2), type: 'public-key', authenticatorAttachment: 'cross-platform',
  getClientExtensionResults: () => ({}),
  response: { clientDataJSON: buf(3), authenticatorData: buf(4), signature: buf(5), attestationObject: buf(6), userHandle: null },
}
const credentials = { get: vi.fn(async () => answer), create: vi.fn(async () => answer) }
const options = { publicKey: { challenge: 'AQID', rpId: 'gw.example.test', user: { id: 'dQ', name: 'kim', displayName: 'Kim' }, rp: { id: 'gw.example.test', name: 'Zanskar' }, pubKeyCredParams: [] } }

beforeEach(() => {
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true })
  ;(window as unknown as { PublicKeyCredential: unknown }).PublicKeyCredential = function PublicKeyCredential() {}
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  credentials.get.mockClear()
  credentials.create.mockClear()
})

const kim = { id: 'u1', username: 'kim', display_name: 'Kim', roles: ['admin'] }

// A sign-in whose second step a security key answers (ADR 0028), and a first
// sign-in that registers a key as the account's first second factor.
describe('Login with a security key', () => {
  function mount(pending: 'verify' | 'enroll', app: boolean, signedIn: () => boolean) {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') {
        if (signedIn()) return { user: kim, csrf_token: 't', mfa_enrolled: true } as never
        return { pending, csrf_token: 't', mfa_enrolled: pending === 'verify', second_factor: { app, keys: pending === 'verify' ? 1 : 0, keys_off: '' } } as never
      }
      if (path === '/auth/providers') return { items: [] } as never
      return { text: '' } as never
    })
    render(
      <MemoryRouter initialEntries={['/login']}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="*" element={<div data-testid="landed" />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    )
  }

  it('signs in with the key; the code field asks for a recovery code when there is no app', async () => {
    let done = false
    const post = vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
      if (path === '/auth/mfa/webauthn/begin') return options as never
      if (path === '/auth/mfa/webauthn/verify') {
        done = true
        return { status: 'ok', csrf_token: 't2' } as never
      }
      throw new ApiError(404, { code: 'not_found', message: path }, '404')
    })
    mount('verify', false, () => done)
    expect(await screen.findByLabelText('Recovery code')).toBeDefined()
    await userEvent.setup().click(await screen.findByRole('button', { name: /Use your key/ }))
    expect(await screen.findByTestId('landed')).toBeDefined()
    expect(post).toHaveBeenCalledWith('/auth/mfa/webauthn/begin', { purpose: 'sign_in' })
    expect(post).toHaveBeenCalledWith('/auth/mfa/webauthn/verify', expect.objectContaining({ credential: expect.objectContaining({ rawId: 'AQI' }) }))
  })

  it('registers a key as the first second factor and shows the recovery codes once', async () => {
    let done = false
    vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
      if (path === '/auth/mfa/totp/enroll') return { secret: 'S', otpauth_url: 'otpauth://totp/x' } as never
      if (path === '/auth/mfa/webauthn/begin') return options as never
      if (path === '/auth/mfa/webauthn/register') {
        done = true
        return { recovery_codes: ['AAAAA-BBBBB'], csrf_token: 't2' } as never
      }
      throw new ApiError(404, { code: 'not_found', message: path }, '404')
    })
    mount('enroll', false, () => done)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Use a security key instead' }))
    expect(await screen.findByText('AAAAA-BBBBB')).toBeDefined()
    expect(credentials.create).toHaveBeenCalledOnce()
    await userEvent.setup().click(screen.getByRole('button', { name: 'I have saved them' }))
    await waitFor(() => expect(screen.getByTestId('landed')).toBeDefined())
  })
})
