import { cleanup, render, screen, waitFor } from '@testing-library/react'
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

const web: Target = {
  id: 't1', name: 'web-01', address: '10.0.0.5', os_family: 'linux', ports: { ssh: 22 }, capabilities: ['ssh'],
  host_key_fingerprint: null, host_key_status: 'trusted', tls_fingerprint: null, winrm_tls_fingerprint: null,
  tags: {}, status: 'active', notes: '', credentials: {}, created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', last_probed_at: null,
}

/** Drawer holds the target the way the targets page does: what a save returns is shown. */
function Drawer() {
  const [t, setT] = useState(web)
  return (
    <>
      <TargetDetail target={t} credentials={[]} onClose={() => {}} onChanged={setT} onDeleted={() => {}} onError={() => {}} />
      <output>status {t.status}</output>
    </>
  )
}

// B25: Disable had no busy state, so a double-click sent two PUTs, and once
// the first had answered the second turned the target back on.
describe('TargetDetail, Disable', () => {
  it('sends one change while the first is in flight', async () => {
    let answer: (t: Target) => void = () => {}
    const put = vi.spyOn(api, 'put').mockImplementation(() => new Promise((resolve) => { answer = resolve as (t: Target) => void }))
    render(<Drawer />)

    await userEvent.setup().dblClick(screen.getByRole('button', { name: 'Disable' }))
    answer({ ...web, status: 'disabled' })

    expect(await screen.findByText('status disabled')).toBeDefined()
    expect(put).toHaveBeenCalledTimes(1)
  })

  it('is not undone by the second click of a double-click', async () => {
    const put = vi.spyOn(api, 'put').mockImplementation(async (_path: string, body?: unknown) => ({ ...web, status: (body as Target).status }) as never)
    render(<Drawer />)

    await userEvent.setup().dblClick(screen.getByRole('button', { name: 'Disable' }))

    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeDefined())
    expect(screen.getByText('status disabled')).toBeDefined()
    expect(put).toHaveBeenCalledTimes(1)
  })
})
