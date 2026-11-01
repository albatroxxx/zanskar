import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { ReachableTarget } from '../../api/types'
import { recordedIntents } from './intent'
import { Targets } from './Targets'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  localStorage.clear()
  document.removeEventListener('click', stay)
})

/** stay keeps a clicked link from navigating, which jsdom cannot do; the
 *  link's own click handler still runs. */
function stay(e: Event) {
  e.preventDefault()
}

/** sessionLink checks a link opens a session in a tab of its own (ADR 0038). */
function sessionLink(name: string, href: string) {
  const a = screen.getByRole('link', { name: `${name}, opens in a new tab` })
  expect([a.getAttribute('href'), a.getAttribute('target'), a.getAttribute('rel')]).toEqual([href, '_blank', 'noopener noreferrer'])
  return a
}

const records = () => recordedIntents()

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

  // 2026-11-01: Open connected in this tab; it opens a tab of its own now,
  // which connects (connect.test.tsx).
  it('lists the application under its own tab and opens it in a tab of its own', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? [wiki] : [] }) as never)
    const post = vi.spyOn(api, 'post')
    document.addEventListener('click', stay)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )
    // With no hosts, the first tab that has something in it is chosen.
    expect(await screen.findByRole('tab', { name: 'Applications (1)', selected: true })).toBeDefined()
    // No address column: where the browser goes is the gateway's business.
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'Tags', 'Open'])

    await userEvent.setup().click(sessionLink('Open Wiki', '/connect?target=a1&protocol=http'))

    expect(records()).toEqual(['/connect?target=a1&protocol=http'])
    expect(post).not.toHaveBeenCalled()
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
    expect(screen.queryByRole('link', { name: /^Open/ })).toBeNull()
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
// ADR 0038: each protocol opens its session in a tab of its own, so a user
// can run several; the click leaves the record the new tab connects on, a
// middle click too. A protocol that cannot connect stays a disabled button.
describe('Targets, sessions in tabs of their own', () => {
  const box: ReachableTarget = {
    kind: 'target', id: 't1', name: 'box', os_family: 'linux', tags: {},
    capabilities: ['ssh', 'vnc'], allowed_protocols: ['ssh', 'vnc'], requires_approval: [], host_key_ready: true,
  }

  function mount(items: ReachableTarget[]) {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => {
      if (p === '/me/autoscaling-groups/g1/instances') return { items: [{ id: 'i9', instance_id: 'i-0abc', availability_zone: 'eu-1a', launched_at: '2026-11-01T08:00:00Z' }] } as never
      return { items: p === '/me/targets' ? items : [] } as never
    })
    document.addEventListener('click', stay)
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    )
  }

  it('links each protocol to a tab of its own, and a click or a middle click leaves the record', async () => {
    const post = vi.spyOn(api, 'post')
    mount([box])
    await screen.findByText('box')
    const ssh = sessionLink('SSH', '/connect?target=t1&protocol=ssh')
    sessionLink('VNC', '/connect?target=t1&protocol=vnc')
    await userEvent.setup().click(ssh)
    ssh.dispatchEvent(new MouseEvent('auxclick', { bubbles: true, button: 1 }))
    ssh.dispatchEvent(new MouseEvent('auxclick', { bubbles: true, button: 2 }))
    expect(records()).toEqual(['/connect?target=t1&protocol=ssh', '/connect?target=t1&protocol=ssh'])
    expect(post).not.toHaveBeenCalled()
  })

  it('counts open sessions again when its tab is looked at, a session having started in another', async () => {
    mount([box])
    await screen.findByText('box')
    const reads = () => vi.mocked(api.get).mock.calls.filter((c) => c[0] === '/me/sessions?open=true&limit=50').length
    expect(reads()).toBe(1)
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    expect(reads()).toBe(1)
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
    expect(reads()).toBe(2)
    delete (document as unknown as Record<string, unknown>).visibilityState
  })

  it('keeps a host whose key is not trusted yet a disabled button, not a link', async () => {
    mount([{ ...box, host_key_ready: false }])
    await screen.findByText('box')
    expect(screen.queryByRole('link', { name: /^SSH/ })).toBeNull()
    expect((screen.getByRole('button', { name: 'SSH' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('offers "as me" where a grant allows it, a link whose tab asks for the login', async () => {
    mount([{ ...box, own_login: ['ssh'] }, { ...box, id: 't2', name: 'other', own_login: [] }])
    await screen.findByText('other')
    expect(screen.getAllByRole('link', { name: /with my own login/ })).toHaveLength(1)
    sessionLink('SSH with my own login', '/connect?target=t1&protocol=ssh&own=1')
  })

  it('opens the instance chooser here, and each instance, or the newest, in a tab of its own', async () => {
    const fleet: ReachableTarget = { ...box, kind: 'asg', id: 'g1', name: 'web-fleet', healthy_count: 1, instance_count: 1 }
    mount([fleet])
    const user = userEvent.setup()
    await user.click(await screen.findByRole('tab', { name: /Autoscaling/ }))
    await user.click(screen.getByRole('button', { name: 'SSH' }))
    await screen.findByRole('dialog', { name: 'Connect to web-fleet' })
    await screen.findByText('i-0abc')
    await user.click(sessionLink('Connect to i-0abc', '/connect?asg=g1&instance=i9&protocol=ssh'))
    sessionLink('Connect to newest healthy', '/connect?asg=g1&protocol=ssh')
    // The chooser stays, so another instance can be opened from it.
    expect(screen.getByRole('dialog', { name: 'Connect to web-fleet' })).toBeDefined()
    expect(records()).toEqual(['/connect?asg=g1&instance=i9&protocol=ssh'])
  })
})
