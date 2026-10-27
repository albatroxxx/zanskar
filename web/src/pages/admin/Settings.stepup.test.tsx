import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { RuntimeSetting, SettingsListing } from '../../api/types'
import { Settings } from './Settings'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const guacd: RuntimeSetting = { key: 'desktop.guacd_addr', category: 'Desktops', title: 'guacd address', description: 'host:port of guacd.', type: 'hostport', default: '', value: '127.0.0.1:4822', source: 'environment', env_var: 'ZANSKAR_GUACD_ADDR', step_up: true }
const listing: SettingsListing = { runtime: [guacd], boot: [] }
const stepUp = () => new ApiError(403, { code: 'step_up_required', message: 'prove your authenticator first' }, '403')

function serve() {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/settings') return listing as never
    if (path === '/admin/system/status') return { env_file: { state: 'unchanged', changed: [] } } as never
    if (path === '/admin/tls') return { mode: 'proxy' } as never
    if (path === '/admin/storage') return { source: 'local', counts: {}, move: { running: false, moved: 0, failed: 0, total: 0 } } as never
    return {} as never
  })
}

// Threat model risk 7: the guacd address decides where the desktop
// credential goes, so the gateway asks for a fresh authenticator code. The
// row asks for the code when told to, proves it, and only then saves.
describe('Settings, a setting that asks for an authenticator code', () => {
  it('shows the code field on step_up_required, proves the code, then saves', async () => {
    serve()
    let proved = false
    const post = vi.spyOn(api, 'post').mockImplementation(async (path: string) => {
      if (path === '/auth/mfa/step-up') proved = true
      return {} as never
    })
    const put = vi.spyOn(api, 'put').mockImplementation(async () => {
      if (!proved) throw stepUp()
      return { ...guacd, value: '10.0.0.5:4822', source: 'console' } as never
    })
    render(<Settings />)
    const user = userEvent.setup()
    const input = await screen.findByLabelText('guacd address')
    await user.clear(input)
    await user.type(input, '10.0.0.5:4822')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    const codeField = await screen.findByLabelText('Authenticator code')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByRole('button', { name: 'Save' }).hasAttribute('disabled')).toBe(true)
    await user.type(codeField, '123456')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(screen.getByText('Applied.')).toBeDefined())
    expect(post).toHaveBeenCalledWith('/auth/mfa/step-up', { code: '123456' })
    expect(put).toHaveBeenCalledTimes(2)
    expect(put.mock.invocationCallOrder[1]).toBeGreaterThan(post.mock.invocationCallOrder[0])
    expect(screen.queryByLabelText('Authenticator code')).toBeNull()
  })

  it('shows a wrong code as an error and keeps the field', async () => {
    serve()
    vi.spyOn(api, 'put').mockRejectedValue(stepUp())
    render(<Settings />)
    const user = userEvent.setup()
    const input = await screen.findByLabelText('guacd address')
    await user.type(input, '1')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(await screen.findByLabelText('Authenticator code'), '000000')
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(401, { code: 'invalid_code', message: 'the code is wrong' }, '401'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect((await screen.findByRole('alert')).textContent).toContain('the code is wrong')
    expect(screen.getByLabelText('Authenticator code')).toBeDefined()
  })
})
