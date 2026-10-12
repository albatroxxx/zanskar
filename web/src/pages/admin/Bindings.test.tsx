import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../api/client'
import type { Credential } from '../../api/types'
import { CredentialBindings } from './Bindings'

afterEach(cleanup)

const key: Credential = {
  id: 'c1', name: 'deploy key', type: 'ssh_key', mode: 'vaulted', has_secret: true, created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z',
}

// B26: a failed save reported the error's bare message, without the
// reference a server error carries for finding its log lines.
describe('CredentialBindings, when a save fails', () => {
  it('reports a server error with its reference', async () => {
    const onError = vi.fn()
    const err = new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500')
    render(<CredentialBindings slots={[{ protocol: 'ssh', label: 'SSH' }]} current={{}} credentials={[key]} onSave={() => Promise.reject(err)} onError={onError} />)

    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('SSH'), 'c1')
    await user.click(screen.getByRole('button', { name: 'Save binding' }))

    expect(onError).toHaveBeenCalledWith('database is locked (reference req-7)')
  })
})
