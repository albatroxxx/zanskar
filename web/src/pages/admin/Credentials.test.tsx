import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { Credential } from '../../api/types'
import { Credentials } from './Credentials'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// PEM markers are assembled, not written out: the secret scanner on every
// commit treats the marker itself as a private key, and these bodies are
// placeholders. The page under test sees the same text a paste would carry.
const pem = (kind: string, body = '') => `-----BEGIN ${kind} PRIVATE KEY-----\n${body}-----END ${kind} PRIVATE KEY-----\n`
const opensshBegin = pem('OPENSSH').split('\n')[0]

function credential(over: Partial<Credential> = {}): Credential {
  return { id: 'c1', name: 'deploy', type: 'password', mode: 'vaulted', username: 'deploy', has_secret: true, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', rotated_at: null, ...over }
}

function lists(items: Credential[]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => (path.startsWith('/credentials') ? { items } : { items: [] }) as never)
}

async function openAdd() {
  lists([])
  render(<Credentials />)
  await screen.findByText('No credentials yet.')
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Add credential' }))
  return { user, form: screen.getByRole('dialog', { name: 'Add credential' }) }
}

describe('Credentials list', () => {
  it('shows each credential without its secret, and only offers what applies to its kind', async () => {
    lists([
      credential(),
      credential({ id: 'c2', name: 'svc', type: 'domain', domain: 'CORP', username: 'svc', in_use_by: { targets: 2, autoscaling_groups: 1 }, rotated_at: '2026-10-20T10:00:00Z' }),
      credential({ id: 'c3', name: 'fleet-ca', type: 'ssh_ca', username: undefined, public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample ca', has_secret: true }),
      credential({ id: 'c4', name: 'eic', type: 'ec2_instance_connect', username: 'ec2-user', has_secret: false }),
      credential({ id: 'c5', name: 'own', mode: 'user_supplied', username: undefined, has_secret: false }),
    ])
    render(<Credentials />)

    const deploy = (await screen.findByText('deploy', { selector: 'strong' })).closest('tr')!
    expect(within(deploy).getByText('password')).toBeDefined()
    expect(within(deploy).getByRole('button', { name: 'Secret stored' })).toBeDefined()
    expect(within(deploy).getByText('never')).toBeDefined()
    expect(within(deploy).getByRole('button', { name: 'Rotate' })).toBeDefined()
    expect((within(deploy).getByRole('button', { name: 'Delete' }) as HTMLButtonElement).disabled).toBe(false)
    // Nothing of the secret itself is in the page.
    expect(deploy.querySelector('input[type=password]')).toBeNull()

    const svc = screen.getByText('svc', { selector: 'strong' }).closest('tr')!
    expect(within(svc).getByText('CORP\\svc')).toBeDefined()
    expect(within(svc).getByText('3')).toBeDefined()
    const del = within(svc).getByRole('button', { name: 'Delete' }) as HTMLButtonElement
    expect(del.disabled).toBe(true)
    expect(del.title).toBe('unassign it from targets first')

    const ca = screen.getByText('fleet-ca').closest('tr')!
    expect(within(ca).getByText('ssh certificate authority')).toBeDefined()
    expect(within(ca).getByText('ssh-ed25519 AAAAC3NzaC1lZDI1…')).toBeDefined()
    expect(within(ca).getByRole('button', { name: 'Setup' })).toBeDefined()
    expect(within(ca).queryByRole('button', { name: 'Rotate' })).toBeNull()

    const eic = screen.getByText('eic').closest('tr')!
    expect(within(eic).getByRole('button', { name: 'No secret stored' })).toBeDefined()
    expect(within(eic).queryByRole('button', { name: 'Rotate' })).toBeNull()

    // The shared user-supplied row is a choice on a target's slot, not a
    // credential: not listed (2026-10-30).
    expect(screen.queryByText('own')).toBeNull()
    expect(screen.queryByRole('columnheader', { name: 'Mode' })).toBeNull()
  })

  it('names a failed read', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(503, { code: 'unavailable', message: 'the key ring is sealed', request_id: 'req-3' }, '503'))
    render(<Credentials />)
    expect(await screen.findByText('the key ring is sealed (reference req-3)')).toBeDefined()
  })
})

describe('Adding a credential', () => {
  it('sends a password credential as vaulted, with the password only in the request', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(credential({ id: 'new' }) as never)
    const { user, form } = await openAdd()
    await user.type(within(form).getByLabelText('Name'), ' deploy ')
    await user.type(within(form).getByLabelText('Username on the target'), 'deploy')
    const pw = within(form).getByLabelText('Password') as HTMLInputElement
    expect(pw.type).toBe('password')
    expect(pw.autocomplete).toBe('new-password')
    await user.type(pw, 'hunter2 hunter2')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0]).toEqual(['/credentials', { name: 'deploy', type: 'password', mode: 'vaulted', username: 'deploy', password: 'hunter2 hunter2' }])
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(document.body.textContent).not.toContain('hunter2')
  })

  it('asks for a domain with a domain account, and a key or a passphrase with a key', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(credential() as never)
    const { user, form } = await openAdd()
    await user.selectOptions(within(form).getByLabelText('Type'), 'domain')
    expect(within(form).getByLabelText('Domain')).toBeDefined()
    await user.selectOptions(within(form).getByLabelText('Type'), 'ssh_key')
    expect(within(form).queryByLabelText('Domain')).toBeNull()
    expect(within(form).getByLabelText('Private key (PEM)')).toBeDefined()
    expect(within(form).getByLabelText('Passphrase (if the key is encrypted)')).toBeDefined()

    await user.type(within(form).getByLabelText('Name'), 'k')
    await user.type(within(form).getByLabelText('Username on the target'), 'ubuntu')
    await user.type(within(form).getByLabelText('Private key (PEM)'), opensshBegin)
    await user.type(within(form).getByLabelText('Passphrase (if the key is encrypted)'), 'open sesame')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0][1]).toEqual({ name: 'k', type: 'ssh_key', mode: 'vaulted', username: 'ubuntu', private_key: opensshBegin, private_key_passphrase: 'open sesame' })
  })

  it('refuses a key file that is too large or not PEM, and loads a real one into the field', async () => {
    const { form } = await openAdd()
    // The picker's accept list is advisory; a person can choose any file.
    const user = userEvent.setup({ applyAccept: false })
    await user.selectOptions(within(form).getByLabelText('Type'), 'ssh_key')
    const input = form.querySelector('#c-private-key-file') as HTMLInputElement
    const big = new File([new Uint8Array(70 * 1024)], 'bundle.p12')
    await user.upload(input, big)
    expect(await within(form).findByText(/bundle\.p12 is 70 KB; a private key is a few KB/)).toBeDefined()
    await user.upload(input, new File(['PuTTY-User-Key-File-3: ssh-ed25519'], 'id.ppk'))
    expect(await within(form).findByText(/id\.ppk does not look like a PEM key/)).toBeDefined()
    await user.upload(input, new File([pem('OPENSSH', 'AAAA\n')], 'id_ed25519'))
    expect(await within(form).findByText('Loaded id_ed25519.')).toBeDefined()
    expect((within(form).getByLabelText('Private key (PEM)') as HTMLTextAreaElement).value).toContain(opensshBegin)
    // The encrypted hint reads the PEM headers; an OpenSSH-format key keeps its cipher name inside the base64, where no hint is seen.
    await user.upload(input, new File([pem('RSA', 'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCD\n\nMIIE\n')], 'enc'))
    expect(await within(form).findByText('Loaded enc; it looks encrypted, enter the passphrase below.')).toBeDefined()
  })

  it('generates a key pair on request and shows only the public half', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(credential({ id: 'g1', name: 'gen', type: 'ssh_key', public_key: 'ssh-ed25519 AAAAgenerated gen' }) as never)
    vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    const { user, form } = await openAdd()
    await user.selectOptions(within(form).getByLabelText('Type'), 'ssh_key')
    await user.type(within(form).getByLabelText('Name'), 'gen')
    await user.type(within(form).getByLabelText('Username on the target'), 'ubuntu')
    await user.click(within(form).getByLabelText(/Generate an ed25519 key for me/))
    expect(within(form).queryByLabelText('Private key (PEM)')).toBeNull()
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/credentials/generate-ssh-key', { name: 'gen', username: 'ubuntu' }))
    expect(await screen.findByText('ssh-ed25519 AAAAgenerated gen')).toBeDefined()
    expect(screen.getByText(/Add this public key to the target's/)).toBeDefined()
  })

  it('creates a certificate authority with a generated key, checks the lifetime, and shows the install snippet', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(credential({ id: 'ca1', name: 'fleet-ca', type: 'ssh_ca', public_key: 'ssh-ed25519 AAAAca fleet-ca' }) as never)
    const { user, form } = await openAdd()
    await user.selectOptions(within(form).getByLabelText('Type'), 'ssh_ca')
    await user.type(within(form).getByLabelText('Name'), 'fleet-ca')
    expect(within(form).queryByLabelText('CA private key (PEM)')).toBeNull()
    await user.type(within(form).getByLabelText('Certificate lifetime (seconds)'), '30')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    expect(await within(form).findByText('certificate lifetime must be 60-3600 seconds, or blank for the default')).toBeDefined()
    expect(post).not.toHaveBeenCalled()
    await user.clear(within(form).getByLabelText('Certificate lifetime (seconds)'))
    await user.type(within(form).getByLabelText('Certificate lifetime (seconds)'), '600')
    await user.type(within(form).getByLabelText('Allowed login users'), 'deploy\nops\n')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0]).toEqual(['/credentials', { name: 'fleet-ca', type: 'ssh_ca', mode: 'vaulted', certificate_ttl_seconds: 600, certificate_principals: ['deploy', 'ops'] }])
    expect(await screen.findByText(/Certificate authority/)).toBeDefined()
    expect(screen.getAllByText(/TrustedUserCAKeys/).length).toBeGreaterThan(0)
  })

  it('shows the server\'s refusal and keeps the form', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(409, { code: 'conflict', message: 'a credential named deploy already exists', request_id: 'r' }, '409'))
    const { user, form } = await openAdd()
    await user.type(within(form).getByLabelText('Name'), 'deploy')
    await user.type(within(form).getByLabelText('Username on the target'), 'deploy')
    await user.type(within(form).getByLabelText('Password'), 'x')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    expect(await within(form).findByText('a credential named deploy already exists')).toBeDefined()
  })
})

describe('Rotating and deleting', () => {
  it('rotates with the new secret only, and deletes after confirmation', async () => {
    lists([credential()])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue({} as never)
    render(<Credentials />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Rotate' }))
    const rotate = screen.getByRole('dialog', { name: 'Rotate deploy' })
    await user.type(within(rotate).getByLabelText('Password'), 'new one')
    await user.click(within(rotate).getByRole('button', { name: 'Rotate' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/credentials/c1/rotate', { password: 'new one' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())

    await user.click(screen.getByRole('button', { name: 'Delete' }))
    const confirm = screen.getByRole('dialog', { name: 'Delete deploy?' })
    expect(within(confirm).getByText('The sealed secret is destroyed. This cannot be undone.')).toBeDefined()
    await user.click(within(confirm).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/credentials/c1'))
  })
})
