import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Target } from '../../api/types'
import { TargetForm } from './TargetForm'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const host: Target = {
  id: 't1', name: 'web-1', address: '10.0.0.5', os_family: 'linux', ports: { ssh: 22 }, capabilities: ['ssh'],
  host_key_fingerprint: 'SHA256:abc', host_key_status: 'trusted', tls_fingerprint: null, winrm_tls_fingerprint: null,
  tags: {}, status: 'active', notes: '', credentials: {}, created_at: '', updated_at: '', last_probed_at: null,
}

// Changing a host's address clears its trusted key and pinned certificates
// on save; the form says so before the admin saves.
describe('TargetForm address', () => {
  const warning = /saving clears the trusted host key/

  it('warns when an existing host is given a new address', async () => {
    render(<TargetForm initial={host} onClose={() => {}} onSaved={() => {}} />)
    expect(screen.queryByText(warning)).toBeNull()
    const address = screen.getByDisplayValue('10.0.0.5')
    await userEvent.clear(address)
    await userEvent.type(address, '10.0.0.6')
    expect(screen.getByText(warning)).toBeDefined()
  })

  it('does not warn for a new target', async () => {
    render(<TargetForm kind="host" onClose={() => {}} onSaved={() => {}} />)
    await userEvent.type(document.getElementById('t-address')!, '10.0.0.6')
    expect(screen.queryByText(warning)).toBeNull()
  })
})

// An application (ADR 0034) is its upstream; it has no label, ports, OS or
// recordings, and its CA bundle appears only for an https upstream.
describe('TargetForm application', () => {
  it('asks for the upstream alone, and sends it as an application', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'a1' } as never)
    const saved = vi.fn()
    render(<TargetForm onClose={() => {}} onSaved={saved} />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('tab', { name: 'Application' }))
    expect(screen.queryByLabelText('Operating system')).toBeNull()
    expect(screen.queryByLabelText(/Keep recordings/)).toBeNull()
    expect(screen.queryByLabelText(/CA bundle/)).toBeNull()

    await user.type(screen.getByLabelText('Name'), 'Wiki')
    await user.type(screen.getByLabelText('Upstream'), 'https://wiki.internal:8443')
    expect(screen.getByLabelText(/CA bundle/)).toBeDefined()
    expect(screen.queryByLabelText('Label')).toBeNull()
    expect(screen.getByText('The only origin the isolated browser can reach')).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Create' }))

    expect(post).toHaveBeenCalledWith('/targets', expect.objectContaining({ name: 'Wiki', address: '', os_family: 'other', engine: '', app_upstream: 'https://wiki.internal:8443', retention_days: null, ports: {} }))
    expect((post.mock.calls[0][1] as Record<string, unknown>)).not.toHaveProperty('app_label')
    expect(saved).toHaveBeenCalled()
  })
})

// B28: the Host and Database choice on a new target showed which one was
// picked only by its styling.
describe('TargetForm kind', () => {
  it('is a tab list that says which kind is picked', async () => {
    render(<TargetForm onClose={() => {}} onSaved={() => {}} />)

    const tabs = screen.getByRole('tablist', { name: 'Kind of target' })
    expect(screen.getByRole('tab', { name: 'Host' }).getAttribute('aria-selected')).toBe('false')
    expect(tabs.querySelectorAll('[tabindex="0"]')).toHaveLength(1)

    await userEvent.click(screen.getByRole('tab', { name: 'Database' }))

    expect(screen.getByRole('tab', { name: 'Database', selected: true })).toBeDefined()
    expect(screen.getByLabelText('Engine')).toBeDefined()
  })
})

// 2026-10-30: tags are rows of a Key and a Value box, not key=value lines.
describe('TargetForm tags', () => {
  it('shows a host\'s tags as rows and sends what the rows say', async () => {
    const put = vi.spyOn(api, 'put').mockResolvedValue(host as never)
    render(<TargetForm initial={{ ...host, tags: { env: 'prod', team: 'ops' } }} onClose={() => {}} onSaved={() => {}} />)
    const user = userEvent.setup()
    expect((screen.getByLabelText('Tag 1 key') as HTMLInputElement).value).toBe('env')
    expect((screen.getByLabelText('Tag 2 value') as HTMLInputElement).value).toBe('ops')
    await user.click(screen.getByRole('button', { name: 'Remove tag team' }))
    await user.click(screen.getByRole('button', { name: 'Add tag' }))
    await user.type(screen.getByLabelText('Tag 2 key'), 'role')
    await user.type(screen.getByLabelText('Tag 2 value'), 'web')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(put).toHaveBeenCalledWith('/targets/t1', expect.objectContaining({ tags: { env: 'prod', role: 'web' } }))
  })

  it('names the bad row and sends nothing', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'x' } as never)
    render(<TargetForm kind="host" onClose={() => {}} onSaved={() => {}} />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Name'), 'web-2')
    await user.type(document.getElementById('t-address')!, '10.0.0.7')
    await user.click(screen.getByRole('button', { name: 'Add tag' }))
    await user.type(screen.getByLabelText('Tag 1 value'), 'prod')
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('tag 1: key is empty')).toBeDefined()
    expect(post).not.toHaveBeenCalled()
  })
})

// 2026-10-30, the walkthrough of Add host: "Address" said nothing of what
// to type; every port showed whatever the operating system, under "blank =
// default"; and "Keep recordings (days)" said "Blank = the policy's or
// global".
describe('TargetForm host fields', () => {
  it('names the address, and shows the ports the operating system uses', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ max_age_days: 90, max_total_bytes: 0 } as never)
    render(<TargetForm kind="host" onClose={() => {}} onSaved={() => {}} />)
    const user = userEvent.setup()
    expect(screen.getByLabelText('Hostname or IP address')).toBeDefined()
    const ports = () => ['SSH', 'RDP', 'VNC', 'WinRM'].filter((p) => screen.queryByLabelText(`${p} port`))
    expect(ports()).toEqual(['SSH'])
    expect((screen.getByLabelText('SSH port') as HTMLInputElement).value).toBe('22')
    await user.click(screen.getByRole('button', { name: 'More ports (VNC)' }))
    expect(ports()).toEqual(['SSH', 'VNC'])
    await user.selectOptions(screen.getByLabelText('Operating system'), 'windows')
    expect(ports()).toEqual(['SSH', 'RDP', 'WinRM']) // More was opened: Windows' SSH shows
    await user.selectOptions(screen.getByLabelText('Operating system'), 'other')
    expect(ports()).toEqual(['SSH', 'RDP', 'VNC', 'WinRM'])
    expect(screen.queryByText(/blank = default/i)).toBeNull()
  })

  it('stores a port left at its default as unset, and keeps a changed one in sight', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ max_age_days: 0, max_total_bytes: 0 } as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue(host as never)
    render(<TargetForm kind="host" onClose={() => {}} onSaved={() => {}} />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Name'), 'web-9')
    await user.type(screen.getByLabelText('Hostname or IP address'), '10.0.0.9')
    await user.selectOptions(screen.getByLabelText('Operating system'), 'windows')
    await user.clear(screen.getByLabelText('RDP port'))
    await user.type(screen.getByLabelText('RDP port'), '3390')
    await user.selectOptions(screen.getByLabelText('Operating system'), 'linux')
    // RDP is not a Linux field, but a value of its own is never hidden.
    expect((screen.getByLabelText('RDP port') as HTMLInputElement).value).toBe('3390')
    await user.click(screen.getByRole('button', { name: 'Create' }))
    const body = post.mock.calls[0][1] as { ports: Record<string, number> }
    expect(body.ports).toEqual({ rdp: 3390 })
  })

  it('says what an empty retention falls back to, and in what order', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ max_age_days: 90, max_total_bytes: 0 } as never)
    render(<TargetForm kind="host" onClose={() => {}} onSaved={() => {}} />)
    const field = screen.getByLabelText('Recording retention (days)') as HTMLInputElement
    await vi.waitFor(() => expect(field.placeholder).toBe('Global: 90 days'))
    expect(screen.getByRole('button', { name: /This target's value comes first; left empty, the policy grant's applies, then the global retention/ })).toBeDefined()
  })
})
