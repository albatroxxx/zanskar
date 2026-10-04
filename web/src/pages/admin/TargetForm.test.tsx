import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import type { Target } from '../../api/types'
import { TargetForm } from './TargetForm'

afterEach(cleanup)

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
