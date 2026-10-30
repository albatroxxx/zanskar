import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Target } from '../../api/types'
import { TargetDetail } from './TargetDetail'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const fp = 'SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const pendingKey: Target = {
  id: 't1', name: 'web-01', address: '10.0.0.5', os_family: 'linux', ports: { ssh: 22 }, capabilities: ['ssh'],
  host_key_fingerprint: fp, host_key_status: 'pending', tls_fingerprint: null, winrm_tls_fingerprint: null,
  tags: {}, status: 'active', notes: '', credentials: {}, created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', last_probed_at: '2026-10-06T10:00:00Z',
}

function Drawer({ target }: { target: Target }) {
  const [t, setT] = useState(target)
  return (
    <>
      <TargetDetail target={t} credentials={[]} onClose={() => {}} onChanged={setT} onDeleted={() => {}} onError={() => {}} />
      <output>key {t.host_key_status}</output>
    </>
  )
}

// Review finding F1: trust sending an empty body passed both drawer tests.
// Trusting a key is a decision about one fingerprint, so the fingerprint the
// administrator saw is what goes to the gateway, and the answer is shown.
describe('TargetDetail, trusting a host key', () => {
  it('sends the fingerprint shown in the dialog and shows the trusted target', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ...pendingKey, host_key_status: 'trusted' } as never)
    render(<Drawer target={pendingKey} />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Trust host key' }))
    const dialog = screen.getByRole('dialog', { name: 'Trust this host key?' })
    expect(dialog.textContent).toContain(fp)
    await user.click(within(dialog).getByRole('button', { name: 'Trust' }))
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/targets/t1/host-key/trust', { host_key_fingerprint: fp })
    expect(await screen.findByText('key trusted')).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Trust host key' })).toBeNull()
  })

  it('warns when the key replaces one that was trusted before, and still sends it', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ target: { ...pendingKey, host_key_status: 'trusted' } } as never)
    render(<Drawer target={{ ...pendingKey, host_key_status: 'changed' }} />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Trust host key' }))
    const dialog = screen.getByRole('dialog', { name: 'Trust this host key?' })
    expect(dialog.textContent).toMatch(/Replaces a previously trusted key/)
    await user.click(within(dialog).getByRole('button', { name: 'Trust' }))
    expect(post).toHaveBeenCalledWith('/targets/t1/host-key/trust', { host_key_fingerprint: fp })
    expect(await screen.findByText('key trusted')).toBeDefined()
  })

  it('offers no trust button while the key is already trusted or unknown', () => {
    render(<Drawer target={{ ...pendingKey, host_key_status: 'trusted' }} />)
    expect(screen.queryByRole('button', { name: 'Trust host key' })).toBeNull()
    cleanup()
    render(<Drawer target={{ ...pendingKey, host_key_status: 'unknown', host_key_fingerprint: null }} />)
    expect(screen.queryByRole('button', { name: 'Trust host key' })).toBeNull()
  })
})
