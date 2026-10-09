import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'
import { Login } from './Login'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const wrong = () => new ApiError(401, { code: 'invalid_code', message: 'invalid code' }, '401')
const ended = () => new ApiError(401, { code: 'sign_in_ended', message: 'too many wrong codes; sign in again' }, '401')

async function atCodeStep(verify: () => Promise<never>) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') throw new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
    if (path === '/auth/providers') return { items: [] } as never
    return { text: '' } as never
  })
  vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
    if (path === '/auth/login') return { status: 'mfa_required', csrf_token: 't' } as never
    return verify()
  })
  render(
    <MemoryRouter>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>,
  )
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText('Username'), 'alice')
  await user.type(screen.getByLabelText('Password'), 'a long enough passphrase{Enter}')
  await screen.findByLabelText('Code')
  return user
}

describe('Login', () => {
  it('stays on the code step after a wrong code', async () => {
    const user = await atCodeStep(() => Promise.reject(wrong()))
    await user.type(screen.getByLabelText('Code'), '000000{Enter}')
    expect((await screen.findByRole('alert')).textContent).toBe('invalid code')
    expect(screen.getByLabelText('Code')).toBeDefined()
  })

  // #205: the attempt that ends the sign-in goes back to the password step.
  it('goes back to the password step when too many wrong codes end the sign-in', async () => {
    const user = await atCodeStep(() => Promise.reject(ended()))
    await user.type(screen.getByLabelText('Code'), '000000{Enter}')
    expect((await screen.findByRole('alert')).textContent).toBe('Too many wrong codes. Sign in again.')
    expect(screen.queryByLabelText('Code')).toBeNull()
    expect(screen.getByLabelText('Username')).toBeDefined()
  })
})
