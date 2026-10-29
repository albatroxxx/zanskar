import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
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

// An application (ADR 0034) opens like a desktop: Open asks /connect for a
// ticket under http and the page is the Desktop one; one that needs
// approval offers Request, and the request names it under http.
describe('Targets, applications', () => {
  const wiki: ReachableTarget = {
    kind: 'application', id: 'a1', name: 'Wiki', os_family: 'other', tags: { team: 'docs' },
    capabilities: [], allowed_protocols: ['http'], requires_approval: [], host_key_ready: true,
  }

  it('lists the application under its own tab and opens it through /connect as a desktop', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [wiki] : [] }) as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ticket: 'tk1', expires_at: '2026-10-27T10:01:00Z', ws_path: '/ws/desktop' } as never)
    render(
      <MemoryRouter>
        <Routes>
          <Route path="/" element={<Targets />} />
          <Route path="/desktop" element={<p>desktop page</p>} />
          <Route path="/terminal" element={<p>terminal page</p>} />
        </Routes>
      </MemoryRouter>,
    )
    // With no hosts, the first tab that has something in it is chosen.
    expect(await screen.findByRole('tab', { name: 'Applications (1)', selected: true })).toBeDefined()
    expect(screen.queryByRole('link', { name: 'Open' })).toBeNull()
    // No address column: where the browser goes is the gateway's business.
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'Tags', 'Open'])

    await userEvent.setup().click(screen.getByRole('button', { name: 'Open' }))

    expect(post).toHaveBeenCalledWith('/connect', { target_id: 'a1', protocol: 'http' })
    expect(await screen.findByText('desktop page')).toBeDefined()
  })

  it('shows the refusal when the gateway cannot run the browser', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [wiki] : [] }) as never)
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(501, { code: 'protocol_unavailable', message: 'applications need guacd and a container runtime', request_id: 'r1' }, '501'))
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Open' }))
    expect(await screen.findByText(/applications need guacd and a container runtime/)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Open' }).hasAttribute('disabled')).toBe(false)
  })

  it('offers Request when the policy requires approval', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [{ ...wiki, requires_approval: ['http'] }] : [] }) as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Request' }))
    expect(screen.getByText(/This application requires approval for HTTP/)).toBeDefined()
    await user.type(screen.getByLabelText('Reason'), 'edit the runbook')
    await user.click(screen.getByRole('button', { name: 'Request access' }))
    expect(post).toHaveBeenCalledWith('/me/access-requests', { target_id: 'a1', protocol: 'http', reason: 'edit the runbook', minutes: 60 })
    expect(screen.queryByRole('button', { name: 'Open' })).toBeNull()
  })
})

// A state glyph replaces the words in the row, but never deletes them: the
// label stays for screen readers and on hover.
describe('Targets state glyphs', () => {
  it('marks an untrusted host with a labelled warning, not a sentence badge', async () => {
    const host: ReachableTarget = {
      kind: 'target', id: 't1', name: 'orders-db-host', os_family: 'linux', tags: {},
      capabilities: ['ssh'], allowed_protocols: ['ssh'], requires_approval: [], host_key_ready: false,
    }
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [host] : [] }) as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )

    await screen.findByText('orders-db-host')
    const warn = screen.getByRole('button', { name: /Awaiting host key trust/ })
    expect(warn.getAttribute('aria-expanded')).toBe('false')
    await userEvent.setup().click(warn)
    expect(warn.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByText('Linux')).toBeDefined()
    expect(screen.queryByText('awaiting host key trust')).toBeNull()
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

    const open = (await screen.findByText('Open sessions')).closest('a')
    expect(open?.getAttribute('href')).toBe('/sessions')
    expect(open?.textContent).toContain('1')
    expect(screen.getByText('Pending requests').closest('a')?.getAttribute('href')).toBe('/access')
    expect(screen.getByText('Grants expiring soon').closest('a')?.getAttribute('href')).toBe('/access')
  })

  it('is absent when nothing waits', async () => {
    vi.spyOn(api, 'get').mockImplementation(async () => ({ items: [] }) as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )

    await screen.findByRole('tablist', { name: 'Kinds of target' })
    expect(screen.queryByText('Open sessions')).toBeNull()
    expect(screen.queryByText('Pending requests')).toBeNull()
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

describe('Targets search', () => {
  const web: ReachableTarget = {
    kind: 'target', id: 'h1', name: 'web01', os_family: 'linux', tags: {},
    capabilities: ['ssh'], allowed_protocols: ['ssh'], host_key_ready: true, private_ip: '10.0.0.5',
  }
  const dbHost: ReachableTarget = {
    kind: 'target', id: 'h2', name: 'db-primary', os_family: 'linux', tags: {},
    capabilities: ['ssh'], allowed_protocols: ['ssh'], host_key_ready: true, private_ip: '10.0.0.9',
  }

  it('filters the loaded list by name or IP as the user types, with a named empty state', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [web, dbHost] : [] }) as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )
    await screen.findByText('web01')
    expect(screen.getByText('db-primary')).toBeDefined()
    const user = userEvent.setup()
    const box = screen.getByRole('searchbox', { name: 'Search targets by name or IP' })

    // By name: typing narrows instantly, no refetch.
    await user.type(box, 'web')
    expect(screen.getByText('web01')).toBeDefined()
    expect(screen.queryByText('db-primary')).toBeNull()

    // By private IP.
    await user.clear(box)
    await user.type(box, '10.0.0.9')
    expect(screen.getByText('db-primary')).toBeDefined()
    expect(screen.queryByText('web01')).toBeNull()

    // No match -> named empty state.
    await user.clear(box)
    await user.type(box, 'zzz')
    expect(screen.getByText(/No hosts match/)).toBeDefined()
    expect(screen.queryByText('web01')).toBeNull()
  })
})
