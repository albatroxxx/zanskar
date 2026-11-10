import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { APITokensCard, type APIToken } from './APITokensCard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 10 (ADR 0044): tokens for automation, made with a recent
// code, their secret shown once, revoked with a confirmation.

const future = new Date(Date.now() + 30 * 86400_000).toISOString()
const past = new Date(Date.now() - 86400_000).toISOString()
const tok = (over: Partial<APIToken>): APIToken => ({
  id: 't1', user_id: 'u1', username: 'root', name: 'terraform', prefix: 'zapi_AbCdEfG', created_at: past, expires_at: future, state: 'active', ...over,
})

function mount(items: APIToken[], post: (path: string, body?: unknown) => Promise<unknown> = async () => ({})) {
  const get = vi.spyOn(api, 'get').mockResolvedValue({ items } as never)
  const p = vi.spyOn(api, 'post').mockImplementation(post as never)
  const del = vi.spyOn(api, 'del').mockResolvedValue({} as never)
  render(<APITokensCard />)
  return { get, post: p, del }
}

describe('API tokens', () => {
  it('lists each token by its prefix, never a secret, with its state', async () => {
    mount([tok({}), tok({ id: 't2', name: 'old', revoked_at: past, state: 'revoked' }), tok({ id: 't3', name: 'lapsed', expires_at: past, state: 'expired' })])
    const row = (name: string) => screen.getByText(name).closest('tr') as HTMLElement
    await screen.findByText('terraform')
    expect(within(row('terraform')).getByText('zapi_AbCdEfG…')).toBeDefined()
    expect(within(row('terraform')).getByText('active')).toBeDefined()
    expect(within(row('terraform')).getByText('never')).toBeDefined()
    expect(within(row('old')).getByText('revoked')).toBeDefined()
    expect(within(row('lapsed')).getByText('expired')).toBeDefined()
    // Only a standing token can be revoked.
    expect(within(row('terraform')).getByRole('button', { name: 'Revoke…' })).toBeDefined()
    expect(within(row('old')).queryByRole('button')).toBeNull()
    expect(within(row('lapsed')).queryByRole('button')).toBeNull()
  })

  it('asks for a recent code, then shows the secret once', async () => {
    let proved = false
    const { post } = mount([], async (path, body) => {
      if (path === '/auth/mfa/step-up') {
        proved = true
        return {}
      }
      if (!proved) throw new ApiError(403, { code: 'step_up_required', message: 'prove your authenticator first' }, '403')
      expect(body).toEqual({ name: 'terraform-prod', days: 365 })
      return { ...tok({ name: 'terraform-prod' }), secret: 'zapi_SECRETVALUE' }
    })
    const user = userEvent.setup()
    await screen.findByText('No tokens yet.')
    await user.type(screen.getByLabelText('Token name'), 'terraform-prod')
    await user.selectOptions(screen.getByLabelText('Lifetime'), '365')
    await user.click(screen.getByRole('button', { name: 'Make token' }))
    const code = await screen.findByLabelText('Authenticator code')
    expect((screen.getByRole('button', { name: 'Make token' }) as HTMLButtonElement).disabled).toBe(true)
    await user.type(code, '123456')
    await user.click(screen.getByRole('button', { name: 'Make token' }))
    expect(await screen.findByText('zapi_SECRETVALUE')).toBeDefined()
    expect(screen.getByText(/not shown again/)).toBeDefined()
    expect(screen.queryByLabelText('Authenticator code')).toBeNull()
    expect(post.mock.calls.map(([p]) => p)).toEqual(['/admin/api-tokens', '/auth/mfa/step-up', '/admin/api-tokens'])
    // Dismissed, the secret is gone from the page.
    await user.click(screen.getByRole('button', { name: /Dismiss/ }))
    expect(screen.queryByText('zapi_SECRETVALUE')).toBeNull()
  })

  it('says why a token could not be made', async () => {
    mount([], async () => {
      throw new ApiError(409, { code: 'too_many_tokens', message: 'you hold 20 active tokens, the most there may be; revoke one first' }, '409')
    })
    const user = userEvent.setup()
    await screen.findByText('No tokens yet.')
    await user.type(screen.getByLabelText('Token name'), 'x')
    await user.click(screen.getByRole('button', { name: 'Make token' }))
    expect(await screen.findByText(/revoke one first/)).toBeDefined()
  })

  it('revokes after a confirmation', async () => {
    const { del, get } = mount([tok({})])
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Revoke…' }))
    expect(del).not.toHaveBeenCalled()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/admin/api-tokens/t1'))
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2))
  })

  it('says the list failed rather than that there are none', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new Error('gateway down'))
    render(<APITokensCard />)
    expect(await screen.findByText(/could not be loaded: gateway down/)).toBeDefined()
    expect(screen.queryByText('No tokens yet.')).toBeNull()
  })
})
