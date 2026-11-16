import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { CloudConsole, ConnectResponse, ReachableTarget } from '../../api/types'
import { Targets } from './Targets'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const soon = new Date(Date.now() + 60 * 60_000).toISOString()
const base = { kind: 'cloud' as const, os_family: 'other' as const, capabilities: ['cloud' as const], allowed_protocols: ['cloud' as const], host_key_ready: true }
const prodAdmin: ReachableTarget = { ...base, id: 'c1', name: 'prod-admin', tags: { env: 'prod' }, cloud: { account_id: '111111111111', account_alias: 'prod', role_name: 'Admin', region: 'eu-west-1', console: true, cli: true } }
const prodRead: ReachableTarget = { ...base, id: 'c2', name: 'prod-read', tags: {}, cloud: { account_id: '111111111111', account_alias: 'prod', role_name: 'ReadOnly', console: false, cli: true } }
const devCli: ReachableTarget = { ...base, id: 'c3', name: 'dev-deploy', tags: {}, cloud: { account_id: '222222222222', role_name: 'Deploy', console: true, cli: false } }
const gated: ReachableTarget = { ...base, id: 'c4', name: 'dev-admin', tags: {}, requires_approval: ['cloud'], cloud: { account_id: '222222222222', role_name: 'Admin', console: true, cli: true } }

const session: ConnectResponse = {
  session_id: 's1', expires_at: soon,
  cloud: { token: 'zaws_x', credentials_url: 'https://gw.example/api/v1/cloud/s1/credentials', profile: '[profile zanskar-prod-admin]\ncredential_process = curl -sf --config ~/.zanskar/s1 https://gw.example/api/v1/cloud/s1/credentials\nregion = eu-west-1\n', console: true, cli: true, account_id: '111111111111', account_alias: 'prod', role_name: 'Admin', region: 'eu-west-1', expires_at: soon },
}
const signin: CloudConsole = { action: 'https://signin.aws.amazon.com/federation', fields: { Action: 'login', Issuer: 'https://gw.example', Destination: 'https://eu-west-1.console.aws.amazon.com/', SigninToken: 'tok' }, console_until: soon, duration_honoured: true }

function show(items: ReachableTarget[]) {
  vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p === '/me/targets' ? items : [] }) as never)
  render(
    <MemoryRouter>
      <Targets />
    </MemoryRouter>,
  )
}

/** submitted catches the form a sign-in is posted with, which the page removes once sent. */
function submitted() {
  const forms: HTMLFormElement[] = []
  vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function (this: HTMLFormElement) {
    forms.push(this.cloneNode(true) as HTMLFormElement)
  })
  return forms
}

// A cloud role (ADR 0050) in the portal: the roles under their accounts, a
// door each for the console and the command line as the grant opens them,
// Request where approval gates it. The console sign-in is a POST into a tab
// opened on the click, never a URL; the command-line profile is shown once.
describe('Targets, cloud roles', () => {
  it('lists the roles under their accounts and opens the console by posting into a new tab', async () => {
    show([prodAdmin, prodRead, devCli])
    vi.spyOn(window, 'open').mockReturnValue(null)
    const post = vi.spyOn(api, 'post').mockImplementation(async (p: string) => (p === '/connect' ? session : signin) as never)
    const forms = submitted()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('tab', { name: 'Cloud (3)' }))
    const heads = screen.getAllByRole('columnheader').map((th) => th.textContent)
    expect(heads).toEqual(['Role', 'Tags', 'Console', 'Command line', '222222222222', 'prod · 111111111111'])
    const row = screen.getByText('prod-admin').closest('tr')!
    expect(within(row).getByText('Admin')).toBeDefined()

    await user.click(within(row).getByRole('button', { name: 'Open the console of prod-admin, opens in a new tab' }))
    await waitFor(() => expect(forms).toHaveLength(1))
    expect(post).toHaveBeenNthCalledWith(1, '/connect', { target_id: 'c1', protocol: 'cloud' })
    expect(post).toHaveBeenNthCalledWith(2, '/cloud/s1/console', {})
    const form = forms[0]
    expect([form.method, form.action, form.target]).toEqual(['post', 'https://signin.aws.amazon.com/federation', '_blank'])
    const fields = Object.fromEntries([...form.querySelectorAll('input')].map((i) => [i.name, [i.type, i.value]]))
    expect(fields).toEqual({ Action: ['hidden', 'login'], Issuer: ['hidden', 'https://gw.example'], Destination: ['hidden', 'https://eu-west-1.console.aws.amazon.com/'], SigninToken: ['hidden', 'tok'] })
    // Nothing of the sign-in is written where the eye can read it.
    expect(screen.queryByText(/tok|federation/)).toBeNull()
    expect(document.querySelector('form[action*="federation"]')).toBeNull()

    // The command line reuses the session this page already has.
    await user.click(within(row).getByRole('button', { name: 'Command line for prod-admin' }))
    const dialog = await screen.findByRole('dialog', { name: 'Command line · prod-admin' })
    expect(within(dialog).getByText(/credential_process = curl/)).toBeDefined()
    expect(within(dialog).getByText(/^Until /)).toBeDefined()
    expect(post.mock.calls.filter(([p]) => p === '/connect')).toHaveLength(1)
  })

  it('closes the door a grant leaves shut', async () => {
    show([prodAdmin, prodRead, devCli])
    const user = userEvent.setup()
    await user.click(await screen.findByRole('tab', { name: 'Cloud (3)' }))
    const disabled = (name: string) => (screen.getByRole('button', { name }) as HTMLButtonElement).disabled
    expect(disabled('Open the console of prod-read, opens in a new tab')).toBe(true)
    expect(disabled('Command line for prod-read')).toBe(false)
    expect(disabled('Open the console of dev-deploy, opens in a new tab')).toBe(false)
    expect(disabled('Command line for dev-deploy')).toBe(true)
  })

  it('starts another session when the remembered one has ended', async () => {
    show([prodAdmin])
    vi.spyOn(window, 'open').mockReturnValue(null)
    let consoles = 0
    const post = vi.spyOn(api, 'post').mockImplementation(async (p: string) => {
      if (p === '/connect') return { ...session, session_id: `s${++consoles}` } as never
      if (p === '/cloud/s1/console') throw new ApiError(410, { code: 'session_ended', message: 'the session has ended' }, 'session ended')
      return signin as never
    })
    submitted()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('tab', { name: 'Cloud (1)' }))
    await user.click(screen.getByRole('button', { name: 'Command line for prod-admin' }))
    await screen.findByRole('dialog', { name: 'Command line · prod-admin' })
    await user.click(screen.getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: 'Open the console of prod-admin, opens in a new tab' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/cloud/s2/console', {}))
    expect(post.mock.calls.map(([p]) => p)).toEqual(['/connect', '/cloud/s1/console', '/connect', '/cloud/s2/console'])
  })

  it('offers Request where approval gates the role, and the request names it under cloud', async () => {
    show([gated])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('tab', { name: 'Cloud (1)' }))
    expect(screen.queryByRole('button', { name: /Open the console/ })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Request' }))
    await user.type(screen.getByLabelText('Reason'), 'incident 42')
    await user.click(screen.getByRole('button', { name: 'Request access' }))
    expect(post).toHaveBeenCalledWith('/me/access-requests', { target_id: 'c4', protocol: 'cloud', reason: 'incident 42', minutes: 60 })
  })
})
