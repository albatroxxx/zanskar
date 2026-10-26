import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AutoscalingGroup, Credential } from '../../api/types'
import { Autoscaling } from './Autoscaling'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const fleet: AutoscalingGroup = {
  id: 'g1', name: 'web-fleet', provider: 'aws', region: 'eu-west-1', external_name: 'web-asg', role_arn: 'arn:aws:iam::123456789012:role/zanskar',
  external_id: 'x1', os_family: 'linux', ports: { ssh: 22 }, capabilities: ['ssh'], address_preference: 'private', poll_interval_seconds: 30,
  tags: {}, status: 'active', last_synced_at: null, credentials: {}, created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z',
}

/** gateway answers the page's reads; the group list returns whatever was last saved. */
function gateway(put: (body: AutoscalingGroup) => Promise<AutoscalingGroup>, credentials: Credential[] = [], start: AutoscalingGroup = fleet) {
  let current = start
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path.startsWith('/autoscaling-groups?')) return { items: [current] } as never
    if (path.startsWith('/autoscaling-groups/g1/instances')) return { items: [] } as never
    if (path.startsWith('/credentials')) return { items: credentials } as never
    throw new Error('no route ' + path)
  })
  return vi.spyOn(api, 'put').mockImplementation(async (_path: string, body?: unknown) => {
    current = await put({ ...fleet, ...(body as Partial<AutoscalingGroup>) })
    return current as never
  })
}

async function openFleet() {
  render(<Autoscaling />)
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: 'Open' }))
  return { user, drawer: within(screen.getByRole('dialog')) }
}

// B25: Disable had no busy state, so a double-click sent two PUTs, and once
// the first had answered the second turned the group back on.
describe('Autoscaling group, Disable', () => {
  it('sends one change while the first is in flight', async () => {
    let answer: () => void = () => {}
    const put = gateway((g) => new Promise((resolve) => { answer = () => resolve(g) }))
    const { user, drawer } = await openFleet()

    await user.dblClick(drawer.getByRole('button', { name: 'Disable' }))
    answer()

    await waitFor(() => expect(drawer.getByRole('button', { name: 'Enable' })).toBeDefined())
    expect(put).toHaveBeenCalledTimes(1)
  })

  it('is not undone by the second click of a double-click', async () => {
    const put = gateway(async (g) => g)
    const { user, drawer } = await openFleet()

    await user.dblClick(drawer.getByRole('button', { name: 'Disable' }))

    await waitFor(() => expect(drawer.getByRole('button', { name: 'Enable' })).toBeDefined())
    expect(put).toHaveBeenCalledTimes(1)
    expect(put.mock.calls[0][1]).toMatchObject({ status: 'disabled' })
  })
})

const credential = (over: Partial<Credential>): Credential => ({
  id: 'c', name: 'c', type: 'password', mode: 'vaulted', has_secret: true, created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', ...over,
})

// D15: the group form had a credential picker of its own, which listed every
// credential, the shared user-supplied row and types that cannot log in over
// the protocol included, and could not offer the user's own login. It is the
// bindings editor's picker now, as the group's drawer has.
describe('Autoscaling group form, credentials', () => {
  it('offers what fits the protocol, and the user\'s own login', async () => {
    const creds = [
      credential({ id: 'k1', name: 'deploy-key', type: 'ssh_key', username: 'ec2-user' }),
      credential({ id: 'd1', name: 'corp', type: 'domain', username: 'svc' }),
      credential({ id: 'u1', name: 'user supplied', mode: 'user_supplied', has_secret: false }),
    ]
    const put = gateway(async (g) => g, creds, { ...fleet, credentials: { ssh: 'u1' } })
    const { user, drawer } = await openFleet()
    await user.click(drawer.getByRole('button', { name: 'Edit' }))

    // Every protocol's switch and port field carries its name for assistive
    // technology, not only the column it sits in.
    expect(drawer.getByLabelText('SSH port')).toBeDefined()
    expect(drawer.getByLabelText('RDP port')).toBeDefined()

    const ssh = document.getElementById('asg-cred-ssh') as HTMLSelectElement
    expect(Array.from(ssh.options).map((o) => o.textContent)).toEqual([
      '— none —',
      'User supplied: ask the user for their own login',
      'deploy-key (ssh key, ec2-user)',
    ])
    expect(ssh.value).toBe('user_supplied')

    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalled())
    expect(put.mock.calls[0][1]).toMatchObject({ credentials: { ssh: 'user_supplied' } })
  })
})
