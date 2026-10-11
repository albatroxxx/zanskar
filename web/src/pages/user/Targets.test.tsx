import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { ReachableTarget } from '../../api/types'
import { Targets } from './Targets'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const fleet: ReachableTarget = {
  kind: 'asg',
  id: 'g1',
  name: 'web-fleet',
  os_family: 'linux',
  tags: {},
  capabilities: ['ssh'],
  allowed_protocols: ['ssh'],
  requires_approval: ['ssh'],
  host_key_ready: true,
  healthy_count: 1,
  instance_count: 1,
}

// M27: an approval-gated autoscaling group showed Connect, which could only
// fail, and had no way to ask for access. It offers Request now, and the
// request names the group.
describe('Targets, an approval-gated autoscaling group', () => {
  it('offers Request, and the request names the group', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [fleet] : [] }) as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )

    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Request' }))
    await user.type(screen.getByLabelText('Reason'), 'deploy')
    await user.click(screen.getByRole('button', { name: 'Request access' }))

    expect(post).toHaveBeenCalledWith('/me/access-requests', { asg_id: 'g1', protocol: 'ssh', reason: 'deploy', minutes: 60 })
  })
})
