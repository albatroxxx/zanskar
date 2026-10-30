import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { StorageStatus } from '../../api/types'
import { StorageCard } from './StorageCard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const idle = { running: false, moved: 0, failed: 0, total: 0 }
const local: StorageStatus = { source: 'local', counts: { local: 4 }, move: idle }
const bucket: StorageStatus = {
  source: 'console',
  active: { bucket: 'rec', prefix: 'zanskar/', region: 'eu-west-1', endpoint: 'https://minio.internal:9000', auth: 'keys', access_key_id: 'AKIAEXAMPLE', secret_set: true },
  counts: { local: 2, 's3://rec': 10, 's3://old': 1 },
  move: idle,
}

function serve(status: StorageStatus) {
  const get = vi.spyOn(api, 'get').mockResolvedValue(status as never)
  return { get, setStatus: (s: StorageStatus) => get.mockResolvedValue(s as never) }
}

describe('StorageCard', () => {
  it('describes the local default and tests, then saves, a bucket with the entered configuration', async () => {
    serve(local)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    render(<StorageCard />)
    const user = userEvent.setup()
    expect(await screen.findByText('local directory')).toBeDefined()
    expect(screen.getByText('4 in local')).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Remove console setting' })).toBeNull()
    const test = screen.getByRole('button', { name: 'Test' }) as HTMLButtonElement
    expect(test.disabled).toBe(true)
    await user.type(screen.getByLabelText('Bucket'), 'rec')
    await user.clear(screen.getByLabelText('Key prefix'))
    await user.type(screen.getByLabelText('Region'), 'eu-west-1')
    expect(screen.queryByLabelText('Secret access key')).toBeNull()
    await user.selectOptions(screen.getByLabelText('Credentials'), 'keys')
    await user.type(screen.getByLabelText('Access key ID'), 'AKIAEXAMPLE')
    const secret = screen.getByLabelText('Secret access key') as HTMLInputElement
    expect(secret.type).toBe('password')
    expect(secret.autocomplete).toBe('new-password')
    await user.type(secret, 'wJalrXUtnFEMI')
    await user.click(test)
    const body = { bucket: 'rec', prefix: 'recordings/', region: 'eu-west-1', endpoint: '', kms_key_id: '', auth: 'keys', access_key_id: 'AKIAEXAMPLE', secret_access_key: 'wJalrXUtnFEMI' }
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/storage/test', body))
    expect(await screen.findByText(/The bucket accepted a probe object/)).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Save and use' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/admin/storage', body))
    expect(await screen.findByText('Saved. The next session records to the bucket.')).toBeDefined()
  })

  it('shows the active bucket without its secret, warns about recordings left elsewhere, and offers the move and the reset', async () => {
    const { setStatus } = serve(bucket)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue({} as never)
    render(<StorageCard />)
    const user = userEvent.setup()
    expect(await screen.findByText('s3://rec/zanskar/')).toBeDefined()
    expect(screen.getByText('Set in console')).toBeDefined()
    expect(screen.getByText(/access key AKIAEXAMPLE/)).toBeDefined()
    expect(screen.getByText('2 in local, 10 in s3://rec, 1 in s3://old')).toBeDefined()
    expect(screen.getByText(/1 recording sit in a bucket that is no longer active/)).toBeDefined()
    // The stored secret is never read back into the form.
    expect((screen.getByLabelText('Secret access key') as HTMLInputElement).value).toBe('')
    expect(screen.getByText('blank keeps the stored secret')).toBeDefined()
    expect((screen.getByLabelText('Access key ID') as HTMLInputElement).value).toBe('')

    await user.click(screen.getByRole('button', { name: 'Move 2 local recordings to the bucket…' }))
    const move = screen.getByRole('dialog', { name: 'Move 2 local recordings?' })
    expect(within(move).getByText(/copied, verified and removed locally/)).toBeDefined()
    setStatus({ ...bucket, move: { running: true, moved: 1, failed: 0, total: 2 } })
    await user.click(within(move).getByRole('button', { name: 'Move' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/storage/move'))
    expect(await screen.findByText('Move started.')).toBeDefined()
    expect(screen.getByText(/Moving… 1 moved, 0 failed\./)).toBeDefined()
    expect(screen.queryByRole('button', { name: /Move 2 local/ })).toBeNull()

    setStatus({ ...bucket, move: { running: false, moved: 2, failed: 0, total: 2, finished_at: '2026-10-26T09:00:00Z' }, counts: { 's3://rec': 12 } })
    await user.click(screen.getByRole('button', { name: 'Remove console setting' }))
    const reset = screen.getByRole('dialog', { name: 'Remove the console storage setting?' })
    expect(within(reset).getByText(/New recordings go to the local directory again/)).toBeDefined()
    await user.click(within(reset).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/admin/storage'))
    expect(await screen.findByText('Console setting removed.')).toBeDefined()
    expect(screen.getByText(/Move finished .*: 2 moved, 0 failed\./)).toBeDefined()
  })

  it('shows a failed probe and keeps the form as entered', async () => {
    serve(local)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(422, { code: 'probe_failed', message: 'AccessDenied: the key cannot write to rec', request_id: 'r' }, '422'))
    render(<StorageCard />)
    const user = userEvent.setup()
    await screen.findByText('local directory')
    await user.type(screen.getByLabelText('Bucket'), 'rec')
    await user.click(screen.getByRole('button', { name: 'Test' }))
    expect(await screen.findByText('AccessDenied: the key cannot write to rec')).toBeDefined()
    expect((screen.getByLabelText('Bucket') as HTMLInputElement).value).toBe('rec')
  })
})
