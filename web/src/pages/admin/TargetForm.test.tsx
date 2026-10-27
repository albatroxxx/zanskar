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
    expect(screen.getByText(/isolated browser beside the gateway/)).toBeDefined()
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
