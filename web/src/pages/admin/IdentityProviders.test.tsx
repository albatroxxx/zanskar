import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { IdentityProviders } from './IdentityProviders'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const okta = {
  id: 'i1', name: 'Okta', type: 'oidc', enabled: true, has_secret: true, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
  config: { oidc: { issuer: 'https://login.example.com', client_id: 'zanskar', client_secret: '', scopes: ['openid', 'email'], allowed_domains: ['example.com'], groups_claim: 'groups' }, default_roles: ['user'], group_mapping: { 'ops-team': 'g1' }, auto_provision: true },
}
const ad = { id: 'i2', name: 'Corp AD', type: 'ldap', enabled: false, has_secret: false, created_at: '2026-10-02T00:00:00Z', updated_at: '2026-10-02T00:00:00Z', config: {} }

function serve(items: unknown[] = [okta, ad]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path.startsWith('/identity-providers/')) return items.find((p) => (p as { id: string }).id === path.split('/')[2]) as never
    if (path.startsWith('/identity-providers')) return { items } as never
    if (path.startsWith('/groups')) return { items: [{ id: 'g1', name: 'ops' }] } as never
    return { items: [] } as never
  })
}

describe('Identity providers list', () => {
  it('shows each provider with its kind, state and whether a secret is stored', async () => {
    serve()
    render(<IdentityProviders />)
    const row = (await screen.findByText('Okta')).closest('tr')!
    expect(within(row).getByText('OIDC')).toBeDefined()
    expect(within(row).getByRole('button', { name: 'Enabled' })).toBeDefined()
    expect(within(row).getByRole('button', { name: 'Secret stored' })).toBeDefined()
    const row2 = screen.getByText('Corp AD').closest('tr')!
    expect(within(row2).getByText('LDAP')).toBeDefined()
    expect(within(row2).getByRole('button', { name: 'Disabled' })).toBeDefined()
    expect(within(row2).getByRole('button', { name: 'No secret stored' })).toBeDefined()
  })

  it('says how to start with none, and names a failed read', async () => {
    serve([])
    const { unmount } = render(<IdentityProviders />)
    expect(await screen.findByText(/No identity providers yet/)).toBeDefined()
    unmount()
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-2' }, '500'))
    render(<IdentityProviders />)
    expect(await screen.findByText('database is locked (reference req-2)')).toBeDefined()
  })
})

describe('Adding a provider', () => {
  async function openAdd() {
    serve([])
    render(<IdentityProviders />)
    await screen.findByText(/No identity providers yet/)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Add provider' }))
    return { user, form: screen.getByRole('dialog', { name: 'Add identity provider' }) }
  }

  it('sends an OpenID Connect provider with its lists parsed and the secret only in the request', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const { user, form } = await openAdd()
    await user.type(within(form).getByLabelText('Name'), ' Okta ')
    await user.type(within(form).getByLabelText('Issuer URL'), 'https://login.example.com')
    await user.type(within(form).getByLabelText('Client ID'), 'zanskar')
    const secret = within(form).getByLabelText('Client secret') as HTMLInputElement
    expect(secret.type).toBe('password')
    await user.type(secret, 's3cr3t')
    await user.type(within(form).getByLabelText('Scopes'), 'openid, email ,groups')
    await user.type(within(form).getByLabelText('Allowed email domains'), 'example.com')
    await user.click(within(form).getByLabelText(/Trust the provider's MFA/))
    await user.click(within(form).getByLabelText('auditor'))
    await user.type(within(form).getByLabelText('Group mapping'), 'ops-team=g1\ncn=dba,ou=groups,dc=corp=g2')
    expect(within(form).getByText('ops=g1')).toBeDefined()
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0]).toEqual(['/identity-providers', {
      name: 'Okta', type: 'oidc', enabled: true,
      config: {
        default_roles: ['user', 'auditor'],
        group_mapping: { 'ops-team': 'g1', 'cn=dba,ou=groups,dc=corp': 'g2' },
        auto_provision: true,
        oidc: { issuer: 'https://login.example.com', client_id: 'zanskar', client_secret: 's3cr3t', scopes: ['openid', 'email', 'groups'], allowed_domains: ['example.com'], skip_mfa: true },
      },
    }])
    expect(document.body.textContent).not.toContain('s3cr3t')
  })

  it('refuses a mapping line it cannot read, and an empty name, before sending', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const { user, form } = await openAdd()
    await user.type(within(form).getByLabelText('Name'), 'x')
    await user.type(within(form).getByLabelText('Group mapping'), 'ops-team')
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    expect(await within(form).findByText('line "ops-team" must be externalGroup=groupId')).toBeDefined()
    await user.clear(within(form).getByLabelText('Group mapping'))
    await user.type(within(form).getByLabelText('Group mapping'), 'ops-team=')
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    expect(await within(form).findByText('line "ops-team=" must be externalGroup=groupId')).toBeDefined()
    expect(post).not.toHaveBeenCalled()
  })

  it('switches to the LDAP fields and sends them under ldap', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const { user, form } = await openAdd()
    await user.selectOptions(within(form).getByLabelText('Type'), 'ldap')
    expect(within(form).queryByLabelText('Issuer URL')).toBeNull()
    await user.type(within(form).getByLabelText('Name'), 'Corp AD')
    await user.type(within(form).getByLabelText('URL'), 'ldaps://dc1.corp.example:636')
    await user.type(within(form).getByLabelText('Bind DN'), 'cn=svc,dc=corp,dc=example')
    await user.type(within(form).getByLabelText('Bind password'), 'bind pw')
    await user.type(within(form).getByLabelText('Base DN'), 'dc=corp,dc=example')
    await user.click(within(form).getByLabelText('Create a Zanskar user on first sign-in'))
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0][1]).toEqual({
      name: 'Corp AD', type: 'ldap', enabled: true,
      config: { default_roles: ['user'], group_mapping: {}, auto_provision: false, ldap: { url: 'ldaps://dc1.corp.example:636', bind_dn: 'cn=svc,dc=corp,dc=example', bind_password: 'bind pw', base_dn: 'dc=corp,dc=example' } },
    })
  })

  it('shows the server\'s refusal and keeps the form', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(422, { code: 'invalid', message: 'issuer must be an https URL', request_id: 'r' }, '422'))
    const { user, form } = await openAdd()
    await user.type(within(form).getByLabelText('Name'), 'x')
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    expect(await within(form).findByText('issuer must be an https URL')).toBeDefined()
    expect(screen.getByRole('dialog', { name: 'Add identity provider' })).toBeDefined()
  })
})

describe('Editing, testing and deleting a provider', () => {
  it('loads the full redacted config, keeps the stored secret when the field is blank, and saves with PUT', async () => {
    serve()
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click((await screen.findAllByRole('button', { name: 'Edit' }))[0])
    const form = screen.getByRole('dialog', { name: 'Edit Okta' })
    await waitFor(() => expect((within(form).getByLabelText('Issuer URL') as HTMLInputElement).value).toBe('https://login.example.com'))
    expect((within(form).getByLabelText('Type') as HTMLSelectElement).disabled).toBe(true)
    const secret = within(form).getByLabelText('Client secret') as HTMLInputElement
    expect(secret.value).toBe('')
    expect(secret.placeholder).toBe('••••••••')
    expect(within(form).getByText('leave blank to keep the stored secret')).toBeDefined()
    expect((within(form).getByLabelText('Scopes') as HTMLInputElement).value).toBe('openid, email')
    expect((within(form).getByLabelText('Group mapping') as HTMLTextAreaElement).value).toBe('ops-team=g1')
    await user.click(within(form).getByLabelText('Enabled'))
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][0]).toBe('/identity-providers/i1')
    expect(put.mock.calls[0][1]).toMatchObject({ enabled: false, config: { oidc: { client_secret: '', issuer: 'https://login.example.com' } } })
  })

  it('reports a connection test as it went', async () => {
    serve()
    const post = vi.spyOn(api, 'post')
      .mockResolvedValueOnce({ status: 'ok' } as never)
      .mockResolvedValueOnce({ status: 'skipped', message: 'OIDC providers are tested at sign-in' } as never)
      .mockResolvedValueOnce({ status: 'failed', message: 'bind refused: invalid credentials' } as never)
      .mockRejectedValueOnce(new ApiError(502, { code: 'upstream', message: 'the directory did not answer', request_id: 'req-8' }, '502'))
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click((await screen.findAllByRole('button', { name: 'Edit' }))[1])
    const form = screen.getByRole('dialog', { name: 'Edit Corp AD' })
    const test = within(form).getByRole('button', { name: 'Test connection' })
    await user.click(test)
    expect(await within(form).findByText('Connection succeeded.')).toBeDefined()
    await user.click(test)
    expect(await within(form).findByText('OIDC providers are tested at sign-in')).toBeDefined()
    await user.click(test)
    expect(await within(form).findByText('bind refused: invalid credentials')).toBeDefined()
    await user.click(test)
    expect(await within(form).findByText('the directory did not answer (reference req-8)')).toBeDefined()
    expect(post).toHaveBeenCalledWith('/identity-providers/i2/test')
  })

  it('deletes after confirmation, and shows a refusal in the dialog', async () => {
    serve()
    const del = vi.spyOn(api, 'del').mockRejectedValueOnce(new ApiError(409, { code: 'conflict', message: 'sessions still open through it', request_id: 'r' }, '409')).mockResolvedValue({} as never)
    render(<IdentityProviders />)
    const user = userEvent.setup()
    await user.click((await screen.findAllByRole('button', { name: 'Delete' }))[0])
    const dialog = screen.getByRole('dialog', { name: 'Delete provider' })
    expect(within(dialog).getByText(/keep their accounts but can no longer sign in with it/)).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    expect(await within(dialog).findByText('sessions still open through it')).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(del).toHaveBeenCalledTimes(2))
    expect(del).toHaveBeenLastCalledWith('/identity-providers/i1')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })
})
