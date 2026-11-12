import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import type { SecondFactor } from '../api/types'
import { AuthProvider } from '../auth/AuthContext'
import { AccountKeys } from './AccountKeys'
import { KeyButton } from './KeyButton'

const buf = (...b: number[]) => new Uint8Array(b).buffer
// What a browser's navigator.credentials answers, with a key (ADR 0028).
const answer = {
  id: 'AQI', rawId: buf(1, 2), type: 'public-key', authenticatorAttachment: 'cross-platform',
  getClientExtensionResults: () => ({}),
  response: { clientDataJSON: buf(3), authenticatorData: buf(4), signature: buf(5), attestationObject: buf(6), userHandle: null },
}
const credentials = { get: vi.fn(async () => answer), create: vi.fn(async () => answer) }

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

const me = (second: SecondFactor) => ({ user: { id: 'u1', username: 'kim', display_name: 'Kim', status: 'active', roles: ['admin'], created_at: '2026-11-01T00:00:00Z' }, csrf_token: 't', mfa_enrolled: second.app || second.keys > 0, second_factor: second })
const options = { publicKey: { challenge: 'AQID', rpId: 'gw.example.test', allowCredentials: [{ type: 'public-key', id: 'AQI' }], user: { id: 'dQ', name: 'kim', displayName: 'Kim' }, rp: { id: 'gw.example.test', name: 'Zanskar' }, pubKeyCredParams: [] } }

describe('the key button at a code prompt', () => {
  it('is not there for an account with no key, and says why keys are off', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(me({ app: true, keys: 0, keys_off: '' }) as never)
    const { unmount } = render(<AuthProvider><KeyButton onDone={() => {}} onError={() => {}} /><span>ready</span></AuthProvider>)
    await screen.findByText('ready')
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(screen.queryByRole('button', { name: /Use your key/ })).toBeNull()
    unmount()

    vi.spyOn(api, 'get').mockResolvedValue(me({ app: false, keys: 1, keys_off: 'No public address is set (ZANSKAR_PUBLIC_URL).' }) as never)
    render(<AuthProvider><KeyButton onDone={() => {}} onError={() => {}} /></AuthProvider>)
    const b = (await screen.findByRole('button', { name: /Use your key/ })) as HTMLButtonElement
    expect(b.disabled).toBe(true)
    expect(b.title).toBe('No public address is set (ZANSKAR_PUBLIC_URL).')
  })

  it('asks the key for the purpose and sends its answer on', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(me({ app: false, keys: 1, keys_off: '' }) as never)
    const post = vi.spyOn(api, 'post').mockImplementation(async (path: string) => (path.endsWith('/begin') ? options : { proved: true }) as never)
    const done = vi.fn()
    render(<AuthProvider><KeyButton onDone={done} onError={() => {}} /></AuthProvider>)
    await userEvent.setup().click(await screen.findByRole('button', { name: /Use your key/ }))
    await waitFor(() => expect(done).toHaveBeenCalled())
    expect(post).toHaveBeenNthCalledWith(1, '/auth/mfa/webauthn/begin', { purpose: 'step_up' })
    const sent = post.mock.calls[1]
    expect(sent[0]).toBe('/auth/mfa/step-up')
    expect((sent[1] as { credential: { rawId: string } }).credential.rawId).toBe('AQI')
    expect(credentials.get).toHaveBeenCalledOnce()
  })

  it('says a cancelled touch in plain words', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(me({ app: false, keys: 1, keys_off: '' }) as never)
    vi.spyOn(api, 'post').mockResolvedValue(options as never)
    credentials.get.mockRejectedValueOnce(new DOMException('x', 'NotAllowedError'))
    const err = vi.fn()
    render(<AuthProvider><KeyButton onDone={() => {}} onError={err} /></AuthProvider>)
    await userEvent.setup().click(await screen.findByRole('button', { name: /Use your key/ }))
    await waitFor(() => expect(err).toHaveBeenCalledWith('Cancelled or timed out.'))
  })
})

describe("the account dialog's security keys", () => {
  const keys = [{ id: 'k1', name: 'YubiKey 5C', created_at: '2026-11-01T00:00:00Z', last_used_at: null, synced: false }]
  function serve(list = keys) {
    return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/auth/me') return me({ app: true, keys: list.length, keys_off: '' }) as never
      if (path === '/auth/mfa/webauthn/keys') return { items: list, app: true, keys_off: '' } as never
      return {} as never
    })
  }

  it('lists the keys and adds one, after a fresh proof when one is asked for', async () => {
    serve()
    let proved = false
    const post = vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
      if (path === '/auth/mfa/webauthn/begin') {
        if (!proved) throw new ApiError(403, { code: 'step_up_required', message: 'prove your second factor first' }, '403')
        return options as never
      }
      if (path === '/auth/mfa/step-up') {
        proved = true
        return { proved: true } as never
      }
      return { key: { id: 'k2' }, recovery_codes: null } as never
    })
    render(<AuthProvider><AccountKeys /></AuthProvider>)
    const user = userEvent.setup()
    expect(await screen.findByText('YubiKey 5C')).toBeDefined()
    await user.type(screen.getByLabelText("New key's name"), 'Laptop')
    await user.click(screen.getByRole('button', { name: 'Add key' }))
    // The gateway asked for a fresh second factor: a code or the key.
    const field = await screen.findByLabelText('Authenticator or recovery code')
    await user.type(field, '123456')
    await user.click(screen.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/auth/mfa/webauthn/register', expect.objectContaining({ name: 'Laptop' })))
    expect(post).toHaveBeenCalledWith('/auth/mfa/step-up', { code: '123456' })
    expect(credentials.create).toHaveBeenCalledOnce()
    expect(screen.queryByLabelText('Authenticator or recovery code')).toBeNull()
  })

  it('renames one, and shows new recovery codes once', async () => {
    serve()
    const patch = vi.spyOn(api, 'patch').mockResolvedValue(undefined as never)
    vi.spyOn(api, 'post').mockResolvedValue({ recovery_codes: ['AAAAA-BBBBB', 'CCCCC-DDDDD'] } as never)
    render(<AuthProvider><AccountKeys /></AuthProvider>)
    const user = userEvent.setup()
    const row = (await screen.findByText('YubiKey 5C')).closest('li')!
    await user.click(within(row).getByRole('button', { name: 'Rename' }))
    const box = screen.getByLabelText('Key name')
    await user.clear(box)
    await user.type(box, 'Desk key')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(patch).toHaveBeenCalledWith('/auth/mfa/webauthn/keys/k1', { name: 'Desk key' }))
    await user.click(await screen.findByRole('button', { name: 'New recovery codes' }))
    expect(await screen.findByText('AAAAA-BBBBB')).toBeDefined()
  })
})
