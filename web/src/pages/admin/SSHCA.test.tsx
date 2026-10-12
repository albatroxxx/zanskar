import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { Credential } from '../../api/types'
import { CASetup } from './SSHCA'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const ca: Credential = {
  id: 'ca1', name: 'fleet-ca', type: 'ssh_ca', mode: 'vaulted', has_secret: true, public_key: 'ssh-ed25519 AAAA fleet-ca',
  created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', in_use_by: { targets: 2 },
}

// B24: when the targets could not be read, the authority's panel said no
// host used it yet, while the line above counted two.
describe('CASetup, when the targets cannot be read', () => {
  it('says so instead of that no host uses the authority', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500'))
    render(<CASetup credential={ca} onClose={() => {}} onSaved={() => {}} />)

    expect(await screen.findByRole('heading', { name: 'Bound targets' })).toBeDefined()
    expect(screen.queryByText(/No host uses this authority/)).toBeNull()
    expect(screen.getByText(/bound targets could not be loaded: database is locked \(reference req-7\)/)).toBeDefined()
  })
})
