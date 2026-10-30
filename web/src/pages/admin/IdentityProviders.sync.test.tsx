import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { IdentityProviders } from './IdentityProviders'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const run = (over: Record<string, unknown> = {}) => ({
  at: '2026-10-30T09:00:00Z', ok: true, listed: 5, created: 2, linked: 0, updated: 0, enabled: 0, disabled: 1, not_created: 0, held: 0, ...over,
})
const kc = {
  id: 'k1', name: 'Keycloak', type: 'oidc', enabled: true, has_secret: true, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
  config: { oidc: { issuer: 'https://kc.example/realms/zanskar', client_id: 'zanskar' }, default_roles: ['user'], auto_provision: true, sync_users: true, sync_minutes: 15 },
  sync: { enabled: true, interval_minutes: 15, running: false, last: run() },
}
const plain = { ...kc, id: 'o1', name: 'Okta', config: { ...kc.config, sync_users: false }, sync: undefined }

function serve(items: unknown[] = [kc, plain]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path.startsWith('/identity-providers/')) return items.find((p) => (p as { id: string }).id === path.split('/')[2]) as never
    if (path.startsWith('/identity-providers')) return { items } as never
    return { items: [] } as never
  })
}

// ADR 0035: the list shows each provider's user sync, and an administrator
// can run it now and read what it did.
describe('Directory user sync in the list', () => {
  it('shows the last run, and runs one now', async () => {
    serve()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ enabled: true, interval_minutes: 15, running: false, last: run({ created: 1, disabled: 0, conflicts: ['bob'] }) } as never)
    render(<IdentityProviders />)
    const row = (await screen.findByText('Keycloak')).closest('tr')!
    expect(within(row).getByRole('button', { name: /5 listed · 2 created · 1 disabled/ })).toBeDefined()
    const other = screen.getByText('Okta').closest('tr')!
    expect(within(other).getByText('At sign-in')).toBeDefined()
    expect(within(other).queryByRole('button', { name: 'Sync now' })).toBeNull()

    const user = userEvent.setup()
    await user.click(within(row).getByRole('button', { name: 'Sync now' }))
    expect(post).toHaveBeenCalledWith('/identity-providers/k1/sync', undefined)
    expect(await screen.findByText('Keycloak: 5 listed · 1 created · 1 in conflict (bob)')).toBeDefined()
  })

  it('names a failed run', async () => {
    serve([{ ...kc, sync: { ...kc.sync, last: run({ ok: false, error: 'keycloak admin API refused the client (HTTP 403)' }) } }])
    vi.spyOn(api, 'post').mockResolvedValue({ enabled: true, interval_minutes: 15, running: false, last: run({ ok: false, error: 'list the directory: HTTP 403' }) } as never)
    render(<IdentityProviders />)
    const row = (await screen.findByText('Keycloak')).closest('tr')!
    expect(within(row).getByRole('button', { name: /Failed .*HTTP 403/ })).toBeDefined()
    await userEvent.setup().click(within(row).getByRole('button', { name: 'Sync now' }))
    expect(await screen.findByText('Keycloak: list the directory: HTTP 403')).toBeDefined()
  })

  it('offers to apply removals a run held back, after a confirmation', async () => {
    serve()
    const held = run({ disabled: 0, held: 4, held_reason: 'would disable 4 of 6 accounts at once; run the sync from the console to apply' })
    const post = vi.spyOn(api, 'post')
      .mockResolvedValueOnce({ enabled: true, interval_minutes: 15, running: false, last: held } as never)
      .mockResolvedValueOnce({ enabled: true, interval_minutes: 15, running: false, last: run({ disabled: 4 }) } as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    const row = (await screen.findByText('Keycloak')).closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Sync now' }))
    const dialog = await screen.findByRole('dialog', { name: 'Apply held removals' })
    expect(within(dialog).getByText(/would disable 4 of 6 accounts at once/)).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Disable 4' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))
    expect(post).toHaveBeenLastCalledWith('/identity-providers/k1/sync', { apply_removals: true })
    expect(await screen.findByText('Keycloak: 5 listed · 2 created · 4 disabled')).toBeDefined()
  })
})

describe('Directory user sync in the form', () => {
  it('turns the sync on with its interval, and holds one out of range back', async () => {
    serve()
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click((await screen.findAllByRole('button', { name: 'Edit' }))[1])
    const form = screen.getByRole('dialog', { name: 'Edit Okta' })
    await waitFor(() => expect((within(form).getByLabelText('Issuer URL') as HTMLInputElement).value).toBe('https://kc.example/realms/zanskar'))
    expect(within(form).queryByLabelText('Sync every (minutes)')).toBeNull()
    await user.selectOptions(within(form).getByLabelText('People arrive'), 'list')
    const minutes = within(form).getByLabelText('Sync every (minutes)') as HTMLInputElement
    expect(minutes.value).toBe('15')
    expect(within(form).getByText(/realm-management › view-users/)).toBeDefined()
    await user.clear(minutes)
    await user.type(minutes, '2')
    // The field's own range stops the save before anything is sent.
    expect(minutes.validity.rangeUnderflow).toBe(true)
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    expect(put).not.toHaveBeenCalled()
    await user.clear(minutes)
    await user.type(minutes, '30')
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][1]).toMatchObject({ config: { sync_users: true, sync_minutes: 30 } })
  })
})

// ADR 0035: any standard provider can push its people over SCIM. The form
// gives the base URL to copy and makes a token, shown once; replacing one
// asks first, since the old one stops working.
describe('SCIM in the form', () => {
  const okta = { ...kc, id: 's1', name: 'Okta', config: { ...kc.config, issuer: 'https://corp.okta.com', sync_users: false, scim: true }, sync: undefined }

  it('shows the base URL and makes a token once', async () => {
    serve([okta])
    const post = vi.spyOn(api, 'post').mockResolvedValue({ token: 'zscim_abc', created_at: '2026-10-30T10:00:00Z', base_path: '/api/v1/scim/s1' } as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    const row = (await screen.findByText('Okta')).closest('tr')!
    expect(within(row).getByRole('button', { name: 'Pushed over SCIM · no token yet' })).toBeDefined()
    await user.click(within(row).getByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('dialog', { name: 'Edit Okta' })
    await waitFor(() => expect((within(form).getByLabelText('People arrive') as HTMLSelectElement).value).toBe('scim'))
    expect((within(form).getByLabelText('SCIM base URL') as HTMLInputElement).value).toBe(`${window.location.origin}/api/v1/scim/s1`)
    expect(within(form).getByText('No token yet')).toBeDefined()
    await user.click(within(form).getByRole('button', { name: 'Make token' }))
    expect(post).toHaveBeenCalledWith('/identity-providers/s1/scim-token')
    expect(((await within(form).findByLabelText('SCIM token')) as HTMLInputElement).value).toBe('zscim_abc')
    expect(within(form).getByText(/Shown once/)).toBeDefined()
  })

  it('asks before replacing a token, and revokes one', async () => {
    serve([{ ...okta, scim_token_created_at: '2026-10-29T10:00:00Z' }])
    const post = vi.spyOn(api, 'post').mockResolvedValue({ token: 'zscim_new', created_at: '2026-10-30T10:00:00Z' } as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue({} as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('dialog', { name: 'Edit Okta' })
    await user.click(await within(form).findByRole('button', { name: 'Replace token' }))
    expect(post).not.toHaveBeenCalled()
    const ask = screen.getByRole('dialog', { name: 'Replace the SCIM token' })
    await user.click(within(ask).getByRole('button', { name: 'Replace' }))
    expect(((await within(form).findByLabelText('SCIM token')) as HTMLInputElement).value).toBe('zscim_new')
    cleanup()
    serve([{ ...okta, scim_token_created_at: '2026-10-29T10:00:00Z' }])
    render(<IdentityProviders />)
    await user.click(await screen.findByRole('button', { name: 'Edit' }))
    const form2 = screen.getByRole('dialog', { name: 'Edit Okta' })
    await user.click(await within(form2).findByRole('button', { name: 'Revoke' }))
    await user.click(within(screen.getByRole('dialog', { name: 'Revoke the SCIM token' })).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/identity-providers/s1/scim-token'))
    expect(await within(form2).findByText('No token yet')).toBeDefined()
  })

  it('saves the choice as scim, and never with the listing', async () => {
    serve([plain])
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('dialog', { name: 'Edit Okta' })
    await waitFor(() => expect((within(form).getByLabelText('Issuer URL') as HTMLInputElement).value).toBe('https://kc.example/realms/zanskar'))
    await user.selectOptions(within(form).getByLabelText('People arrive'), 'scim')
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const config = (put.mock.calls[0][1] as { config: Record<string, unknown> }).config
    expect(config.scim).toBe(true)
    expect(config.sync_users).toBeUndefined()
  })
})


// A provider that publishes no sign-out (Google) passes the test with a
// warning: signing out will end the Zanskar session only.
describe('Connection test and sign-out', () => {
  it('warns when the provider offers no sign-out', async () => {
    serve([plain])
    vi.spyOn(api, 'post').mockResolvedValue({ status: 'ok', provider_sign_out: false } as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('dialog', { name: 'Edit Okta' })
    await user.click(within(form).getByRole('button', { name: 'Test connection' }))
    expect(await within(form).findByText(/offers no sign-out, so signing out ends the Zanskar session only/)).toBeDefined()
  })
})
