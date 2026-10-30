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
    expect(open?.getAttribute('href')).toBe('/sessions?open=1')
    expect(open?.textContent).toContain('1')
    expect(screen.getByText('Pending requests').closest('a')?.getAttribute('href')).toBe('/access?show=pending')
    expect(screen.getByText('Grants expiring soon').closest('a')?.getAttribute('href')).toBe('/access?show=expiring')
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

// 2026-10-30 walkthrough: only Applications (and Databases) said how many
// they held. Every tab counts its own, the same way, once it has any, and a
// search narrows the counts with the lists.
describe('Target tabs count what they hold', () => {
  const host = (id: string, name: string): ReachableTarget => ({ ...fleet, kind: 'target', id, name, private_ip: '10.0.0.' + id.slice(1) })
  const items: ReachableTarget[] = [
    host('h1', 'linux-host'), host('h2', 'windows-host'),
    { ...host('d1', 'orders-db'), engine: 'postgres' },
    { ...fleet, id: 'g1', name: 'web-fleet' },
  ]

  it('counts every kind, and the search narrows the counts', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? items : [] }) as never)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )
    expect(await screen.findByRole('tab', { name: 'Hosts (2)' })).toBeDefined()
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['Hosts (2)', 'Databases (1)', 'Applications', 'Autoscaling (1)'])
    await userEvent.setup().type(screen.getByRole('searchbox', { name: 'Search targets by name or IP' }), 'linux')
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['Hosts (1)', 'Databases', 'Applications', 'Autoscaling'])
  })
})

// 2026-10-30: a slot that asks for the user's own login takes a password, or
// over SSH the user's own private key with its passphrase. What the gateway
// says about it shows in the prompt, and what was typed is forgotten when
// the prompt closes.
describe('Targets, the user\'s own login', () => {
  const box: ReachableTarget = {
    kind: 'target', id: 't1', name: 'box-own', os_family: 'linux', tags: {},
    capabilities: ['ssh', 'vnc'], allowed_protocols: ['ssh', 'vnc'], requires_approval: [], host_key_ready: true,
  }
  const asked = new ApiError(422, { code: 'credential_required', message: 'this target needs your username and password', request_id: 'r' }, '422')

  function mount() {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [box] : [] }) as never)
    render(
      <MemoryRouter>
        <Routes>
          <Route path="/" element={<Targets />} />
          <Route path="/terminal" element={<p>terminal page</p>} />
          <Route path="/desktop" element={<p>desktop page</p>} />
        </Routes>
      </MemoryRouter>,
    )
  }

  it('signs in over SSH with a key and its passphrase, the gateway\'s refusal shown in the prompt', async () => {
    const post = vi.spyOn(api, 'post')
      .mockRejectedValueOnce(asked)
      .mockRejectedValueOnce(new ApiError(422, { code: 'credential_invalid', message: 'the key is encrypted, and its passphrase is missing or wrong', request_id: 'r' }, '422'))
      .mockResolvedValueOnce({ ticket: 'tk', expires_at: 'x', ws_path: '/ws/terminal' } as never)
    mount()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'SSH' }))
    const dialog = await screen.findByRole('dialog', { name: 'Credentials for box-own' })
    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.click(screen.getByRole('radio', { name: 'Private key' }))
    expect(screen.queryByLabelText('Password', { selector: 'input[type=password]' })).toBeNull()
    await user.type(screen.getByLabelText('Private key', { selector: 'textarea' }), 'KEY')
    await user.click(screen.getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('the key is encrypted, and its passphrase is missing or wrong')).toBeDefined()
    expect(dialog.isConnected).toBe(true)
    expect(post.mock.calls[1][1]).toEqual({ target_id: 't1', protocol: 'ssh', credential: { username: 'alice', private_key: 'KEY' } })

    await user.type(screen.getByLabelText('Passphrase'), 'pp')
    await user.click(screen.getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post.mock.calls[2][1]).toEqual({ target_id: 't1', protocol: 'ssh', credential: { username: 'alice', private_key: 'KEY', private_key_passphrase: 'pp' } })
  })

  it('asks a desktop for a password only, and forgets it when the prompt closes', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(asked)
    mount()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'VNC' }))
    await screen.findByRole('dialog', { name: 'Credentials for box-own' })
    expect(screen.queryByLabelText('Private key')).toBeNull()
    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.type(screen.getByLabelText('Password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await user.click(screen.getByRole('button', { name: 'VNC' }))
    await screen.findByRole('dialog', { name: 'Credentials for box-own' })
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('alice')
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('')
  })
})

// ADR 0036: where a grant lets the user sign in with their own login instead
// of the target's, the portal offers "as me" beside the protocol; it asks for
// the login at once, and the connect carries it.
describe('Targets, signing in as me', () => {
  it('offers "as me" where a grant allows it, and sends the login', async () => {
    const box: ReachableTarget = {
      kind: 'target', id: 't1', name: 'box', os_family: 'linux', tags: {}, capabilities: ['ssh'],
      allowed_protocols: ['ssh'], own_login: ['ssh'], requires_approval: [], host_key_ready: true,
    }
    const other: ReachableTarget = { ...box, id: 't2', name: 'other', own_login: [] }
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [box, other] : [] }) as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ticket: 'tk', expires_at: 'x', ws_path: '/ws/terminal' } as never)
    render(
      <MemoryRouter>
        <Routes>
          <Route path="/" element={<Targets />} />
          <Route path="/terminal" element={<p>terminal page</p>} />
        </Routes>
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    expect(await screen.findAllByRole('button', { name: 'SSH with my own login' })).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: 'SSH with my own login' }))
    await screen.findByRole('dialog', { name: 'Credentials for box' })
    expect(post).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('Username'), 'me')
    await user.type(screen.getByLabelText('Password', { selector: 'input[type=password]' }), 'mine')
    await user.click(screen.getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post).toHaveBeenCalledWith('/connect', { target_id: 't1', protocol: 'ssh', credential: { username: 'me', password: 'mine' } })
  })
})
