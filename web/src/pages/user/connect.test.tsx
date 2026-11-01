import { StrictMode } from 'react'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { ReachableTarget } from '../../api/types'
import { ConnectPage } from './connect'
import { connectHref, intentTTL, parseIntent, recordIntent, takeIntent } from './intent'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  localStorage.clear()
  document.title = ''
})

const box: ReachableTarget = {
  kind: 'target', id: 't1', name: 'box', os_family: 'linux', tags: {},
  capabilities: ['ssh', 'vnc'], allowed_protocols: ['ssh', 'vnc'], requires_approval: [], host_key_ready: true,
}
const fleet: ReachableTarget = {
  kind: 'asg', id: 'g1', name: 'web-fleet', os_family: 'linux', tags: {},
  capabilities: ['ssh'], allowed_protocols: ['ssh'], requires_approval: [], host_key_ready: true, healthy_count: 2, instance_count: 2,
}
const wiki: ReachableTarget = {
  kind: 'application', id: 'a1', name: 'Wiki', os_family: 'other', tags: {},
  capabilities: [], allowed_protocols: ['http'], requires_approval: [], host_key_ready: true,
}
const granted = { ticket: 'tk', expires_at: 'x', ws_path: '/ws/terminal' }
const asked = new ApiError(422, { code: 'credential_required', message: 'this target needs your username and password', request_id: 'r' }, '422')

let page = 0
/** open mounts /connect as a new tab does, clicked (a record left for it) or
 *  not. Each mount is its own history entry, like its own page load. */
function open(href: string, { clicked = true, items = [box, fleet, wiki], strict = false } = {}) {
  if (clicked) recordIntent(href)
  vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? items : [] }) as never)
  const url = new URL(href, 'http://localhost')
  const tree = (
    <MemoryRouter initialEntries={[{ pathname: url.pathname, search: url.search, key: `page-${++page}` }]}>
      <Routes>
        <Route path="/connect" element={<ConnectPage />} />
        <Route path="/terminal" element={<p>terminal page</p>} />
        <Route path="/desktop" element={<p>desktop page</p>} />
        <Route path="/" element={<p>targets</p>} />
      </Routes>
    </MemoryRouter>
  )
  render(strict ? <StrictMode>{tree}</StrictMode> : tree)
}

// ADR 0038: a session opens in a tab of its own. The link carries ids only;
// a click leaves a record that the new tab uses up, so that a link from
// anywhere else asks before it connects.
describe('the record of a session link just clicked', () => {
  const href = connectHref({ target: 't1', protocol: 'ssh' })

  it('is used up once, by one tab', () => {
    recordIntent(href)
    expect(takeIntent(href)).toBe(true)
    expect(takeIntent(href)).toBe(false)
    expect(localStorage.getItem('zanskar.connect')).toBeNull()
  })

  it('serves two tabs when the link was clicked twice, and only for its own address', () => {
    recordIntent(href)
    recordIntent(href)
    expect(takeIntent(connectHref({ target: 't1', protocol: 'vnc' }))).toBe(false)
    expect(takeIntent(href)).toBe(true)
    expect(takeIntent(href)).toBe(true)
  })

  it('lapses after a minute, and goes from storage on the next write', () => {
    recordIntent(href, 1_000)
    recordIntent('/connect?target=t2&protocol=ssh', 1_000 + intentTTL)
    expect(localStorage.getItem('zanskar.connect')).not.toContain('t1')
    expect(takeIntent(href, 1_000 + intentTTL)).toBe(false)
  })

  it('reads storage it does not understand as no record', () => {
    localStorage.setItem('zanskar.connect', '{"not":"a list"')
    expect(takeIntent(href)).toBe(false)
    localStorage.setItem('zanskar.connect', JSON.stringify([{ href, at: 'soon' }, 7]))
    expect(takeIntent(href)).toBe(false)
  })
})

describe('a session link', () => {
  it('names a machine, a group or an instance by id, and nothing else', () => {
    expect(connectHref({ target: 't1', protocol: 'ssh', own: true })).toBe('/connect?target=t1&protocol=ssh&own=1')
    expect(connectHref({ asg: 'g1', instance: 'i9', protocol: 'rdp' })).toBe('/connect?asg=g1&instance=i9&protocol=rdp')
    const q = (s: string) => parseIntent(new URLSearchParams(s))
    expect(q('target=t1&protocol=ssh&own=1')).toEqual({ target: 't1', protocol: 'ssh', own: true })
    expect(q('asg=g1&instance=i9&protocol=rdp')).toEqual({ asg: 'g1', instance: 'i9', protocol: 'rdp' })
    for (const bad of ['target=t1&protocol=telnet', 'protocol=ssh', 'target=t1&asg=g1&protocol=ssh', 'instance=i9&protocol=ssh', 'target=../x&protocol=ssh', 'target=t1']) {
      expect(parseIntent(new URLSearchParams(bad))).toBeNull()
    }
  })
})

describe('the tab a session link opened', () => {
  it('connects at once when our own link was just clicked, and opens the terminal in this tab', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(granted as never)
    open('/connect?target=t1&protocol=ssh')
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post.mock.calls).toEqual([['/connect', { target_id: 't1', protocol: 'ssh' }]])
  })

  it('asks first when it was opened any other way, and connects on Connect', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(granted as never)
    open('/connect?target=t1&protocol=ssh', { clicked: false })
    expect(await screen.findByText('Connect to box over SSH?')).toBeDefined()
    expect(document.title).toBe('box · SSH · Zanskar')
    expect(post).not.toHaveBeenCalled()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('connects once under StrictMode, which runs its first steps twice', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(granted as never)
    open('/connect?target=t1&protocol=ssh', { strict: true })
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('opens an application as a desktop', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ...granted, ws_path: '/ws/desktop' } as never)
    open('/connect?target=a1&protocol=http')
    expect(await screen.findByText('desktop page')).toBeDefined()
    expect(post).toHaveBeenCalledWith('/connect', { target_id: 'a1', protocol: 'http' })
  })

  it('reaches an autoscaling group through its newest healthy instance, or the one picked', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(granted as never)
    open('/connect?asg=g1&protocol=ssh')
    expect(await screen.findByText('terminal page')).toBeDefined()
    cleanup()
    open('/connect?asg=g1&instance=i9&protocol=ssh')
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post.mock.calls.map((c) => c[1])).toEqual([{ asg_id: 'g1', protocol: 'ssh' }, { asg_instance_id: 'i9', protocol: 'ssh' }])
  })

  it('refuses a machine or a protocol that is not among the user\'s, without asking the gateway to connect', async () => {
    const post = vi.spyOn(api, 'post')
    open('/connect?target=t9&protocol=ssh')
    expect(await screen.findByText('SSH to that machine is not among your targets.')).toBeDefined()
    cleanup()
    open('/connect?target=t1&protocol=rdp')
    expect(await screen.findByText('RDP to that machine is not among your targets.')).toBeDefined()
    expect(post).not.toHaveBeenCalled()
    expect(screen.getByRole('link', { name: 'Back to targets' }).getAttribute('href')).toBe('/')
  })

  it('says what a link that names nothing is', async () => {
    open('/connect?protocol=ssh', { clicked: false })
    expect(await screen.findByText('This link does not name a machine to connect to.')).toBeDefined()
  })

  it('shows the gateway\'s refusal, and Connect tries again', async () => {
    const post = vi.spyOn(api, 'post')
      .mockRejectedValueOnce(new ApiError(501, { code: 'protocol_unavailable', message: 'applications need guacd and a container runtime', request_id: 'r1' }, '501'))
      .mockResolvedValueOnce({ ...granted, ws_path: '/ws/desktop' } as never)
    open('/connect?target=a1&protocol=http')
    expect(await screen.findByText(/applications need guacd and a container runtime/)).toBeDefined()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('desktop page')).toBeDefined()
    expect(post).toHaveBeenCalledTimes(2)
  })

  it('says a lapsed grant needs a request, with the way to Targets', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(new ApiError(403, { code: 'approval_required', message: 'approval required', request_id: 'r' }, '403'))
    open('/connect?target=t1&protocol=ssh')
    expect(await screen.findByText(/SSH access to box needs an approved request\./)).toBeDefined()
    expect(screen.getByRole('link', { name: 'Request it from Targets' }).getAttribute('href')).toBe('/')
  })
})

// Moved from the Targets page with the prompt (ADR 0036): the user's own
// login is asked for in the tab that connects.
describe('the tab a session link opened, the user\'s own login', () => {
  it('asks for it at once for "as me", and sends it', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(granted as never)
    open('/connect?target=t1&protocol=ssh&own=1')
    const dialog = await screen.findByRole('dialog', { name: 'Credentials for box' })
    expect(post).not.toHaveBeenCalled()
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Username'), 'me')
    await user.type(screen.getByLabelText('Password', { selector: 'input[type=password]' }), 'mine')
    await user.click(within(dialog).getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post).toHaveBeenCalledWith('/connect', { target_id: 't1', protocol: 'ssh', credential: { username: 'me', password: 'mine' } })
  })

  it('signs in over SSH with a key and its passphrase, the gateway\'s refusal shown in the prompt', async () => {
    const post = vi.spyOn(api, 'post')
      .mockRejectedValueOnce(asked)
      .mockRejectedValueOnce(new ApiError(422, { code: 'credential_invalid', message: 'the key is encrypted, and its passphrase is missing or wrong', request_id: 'r' }, '422'))
      .mockResolvedValueOnce(granted as never)
    open('/connect?target=t1&protocol=ssh')
    const user = userEvent.setup()
    const dialog = await screen.findByRole('dialog', { name: 'Credentials for box' })
    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.click(screen.getByRole('radio', { name: 'Private key' }))
    expect(screen.queryByLabelText('Password', { selector: 'input[type=password]' })).toBeNull()
    await user.type(screen.getByLabelText('Private key', { selector: 'textarea' }), 'KEY')
    await user.click(within(dialog).getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('the key is encrypted, and its passphrase is missing or wrong')).toBeDefined()
    expect(dialog.isConnected).toBe(true)
    expect(post.mock.calls[1][1]).toEqual({ target_id: 't1', protocol: 'ssh', credential: { username: 'alice', private_key: 'KEY' } })

    await user.type(screen.getByLabelText('Passphrase'), 'pp')
    await user.click(within(dialog).getByRole('button', { name: 'Connect' }))
    expect(await screen.findByText('terminal page')).toBeDefined()
    expect(post.mock.calls[2][1]).toEqual({ target_id: 't1', protocol: 'ssh', credential: { username: 'alice', private_key: 'KEY', private_key_passphrase: 'pp' } })
  })

  it('asks a desktop for a password only, and forgets it when the prompt closes', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(asked)
    open('/connect?target=t1&protocol=vnc')
    const user = userEvent.setup()
    await screen.findByRole('dialog', { name: 'Credentials for box' })
    expect(screen.queryByLabelText('Private key')).toBeNull()
    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.type(screen.getByLabelText('Password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await user.click(screen.getByRole('button', { name: 'Connect' }))
    await screen.findByRole('dialog', { name: 'Credentials for box' })
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('alice')
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('')
  })
})
