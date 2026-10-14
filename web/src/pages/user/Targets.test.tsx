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

// The overview strip (ADR 0029): a user with something waiting sees it above
// the list; a user with nothing waiting sees no strip at all.
describe('Targets overview strip', () => {
  it('shows open sessions, pending requests and expiring grants, each linking to its page', async () => {
    const soon = new Date(Date.now() + 30 * 60000).toISOString()
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => {
      if (p.startsWith('/me/sessions')) return { items: [{ id: 's1' }] } as never
      if (p === '/me/access-requests') return { items: [{ id: 'r1', status: 'pending' }, { id: 'r2', status: 'approved' }] } as never
      if (p === '/me/access') return { items: [{ id: 'r2', target_id: 't1', protocol: 'ssh', expires_at: soon }] } as never
      return { items: [] } as never
    })
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )

    const open = (await screen.findByText('session of yours is still open')).closest('a')
    expect(open?.getAttribute('href')).toBe('/sessions')
    expect(open?.textContent).toContain('1')
    expect(screen.getByText('access request awaiting approval').closest('a')?.getAttribute('href')).toBe('/access')
    expect(screen.getByText('grant expires within the hour').closest('a')?.getAttribute('href')).toBe('/access')
  })

  it('is absent when nothing waits', async () => {
    vi.spyOn(api, 'get').mockImplementation(async () => ({ items: [] }) as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )

    await screen.findByRole('tablist', { name: 'Kinds of target' })
    expect(screen.queryByText(/still open/)).toBeNull()
    expect(screen.queryByText(/awaiting approval/)).toBeNull()
  })
})

// B28: the Hosts, Databases and Autoscaling tabs showed which one was open
// only by their styling.
describe('Targets tabs', () => {
  it('are a tab list that says which tab is open', async () => {
    vi.spyOn(api, 'get').mockImplementation(async () => ({ items: [] }) as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )

    await screen.findByRole('tablist', { name: 'Kinds of target' })
    expect(screen.getByRole('tab', { name: 'Hosts', selected: true })).toBeDefined()

    await userEvent.setup().click(screen.getByRole('tab', { name: 'Autoscaling' }))

    expect(screen.getByRole('tab', { name: 'Autoscaling', selected: true })).toBeDefined()
    expect(screen.getByRole('tab', { name: 'Hosts' }).getAttribute('aria-selected')).toBe('false')
  })
})
