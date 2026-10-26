import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { Policy } from '../../api/types'
import { Policies } from './Policies'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const groups = [{ id: 'g1', name: 'ops' }, { id: 'g2', name: 'dba' }]
const users = [
  { id: 'u1', username: 'alice', display_name: 'Alice', roles: ['user'], status: 'active' },
  { id: 'u2', username: 'ava', display_name: 'Ava the auditor', roles: ['auditor'], status: 'active' },
]
const targets = [{ id: 't1', name: 'web-1', tags: {} }, { id: 't2', name: 'db-1', tags: {} }]
const asgs = [{ id: 'a1', name: 'fleet' }]

function policy(over: Partial<Policy> = {}): Policy {
  return {
    id: 'p1', name: 'ops-ssh', description: 'Shell on the fleet', enabled: true, group_id: 'g1',
    target_selector: { tags: { env: 'prod' } }, protocols: ['ssh'], time_windows: [],
    idle_timeout_minutes: 15, max_session_minutes: null, allow_clipboard: false, allow_file_transfer: false,
    require_mfa: true, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', ...over,
  }
}

/** lists serves every collection the page reads, with the policies given. */
function lists(policies: Policy[]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    const items = path.startsWith('/access-policies') ? policies : path.startsWith('/groups') ? groups : path.startsWith('/users') ? users : path.startsWith('/targets') ? targets : path.startsWith('/autoscaling-groups') ? asgs : []
    return { items } as never
  })
}

const refused = (status: number, message: string) => new ApiError(status, { code: 'invalid', message, request_id: 'req-1' }, String(status))

describe('Policies list', () => {
  it('shows each policy: who, which protocols, which targets, windows, limits and state', async () => {
    lists([
      policy(),
      policy({ id: 'p2', name: 'alice-rdp', description: '', group_id: undefined, user_id: 'u1', target_selector: { targets: ['t1', 't2'], asgs: ['a1'] }, protocols: ['rdp', 'winrm'], enabled: false, max_session_minutes: 120, time_windows: [{ days: ['mon'], from: '09:00', to: '17:00', tz: 'UTC' }], rules: [{ target_selector: { tags: { role: 'jump' } }, protocols: ['ssh'] }] }),
    ])
    render(<Policies />)

    const first = (await screen.findByText('ops-ssh')).closest('tr')!
    expect(within(first).getByText('ops')).toBeDefined()
    expect(within(first).getByText('group')).toBeDefined()
    expect(within(first).getByText('ssh')).toBeDefined()
    expect(within(first).getByText('env=prod')).toBeDefined()
    expect(within(first).getByText('always')).toBeDefined()
    expect(within(first).getByText('15 m / ∞')).toBeDefined()
    expect(within(first).getByRole('button', { name: 'Enabled' })).toBeDefined()

    const second = screen.getByText('alice-rdp').closest('tr')!
    expect(within(second).getByText('alice')).toBeDefined()
    expect(within(second).getByText('user')).toBeDefined()
    expect(within(second).getByText('web-1, db-1 · ASG fleet')).toBeDefined()
    expect(within(second).getByText('+ 1 rule')).toBeDefined()
    expect(within(second).getByText('ssh → role=jump')).toBeDefined()
    expect(within(second).getByText('15 m / 120 m')).toBeDefined()
    expect(within(second).getByRole('button', { name: 'Disabled' })).toBeDefined()
    // One time window is counted, not spelled out, in the list.
    expect(within(second).getAllByRole('cell')[4].textContent).toBe('1')
  })

  it('says nobody can connect while there is no policy, and names a failed read', async () => {
    lists([])
    const { unmount } = render(<Policies />)
    expect(await screen.findByText('No policies yet. Nobody can connect until a policy grants access.')).toBeDefined()
    unmount()

    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/access-policies')) throw new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-9' }, '500')
      return { items: [] } as never
    })
    render(<Policies />)
    expect(await screen.findByText('database is locked (reference req-9)')).toBeDefined()
    expect(screen.queryByText(/No policies yet/)).toBeNull()
  })
})

describe('Policy form', () => {
  async function openNew() {
    lists([])
    render(<Policies />)
    await screen.findByText(/No policies yet/)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Add policy' }))
    const form = screen.getByRole('dialog', { name: 'Add policy' })
    return { user, form }
  }

  it('refuses what the server would refuse, before sending anything', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const { user, form } = await openNew()
    const create = within(form).getByRole('button', { name: 'Create' })
    await user.type(within(form).getByLabelText('Name'), 'empty')

    // The default form grants ssh on nothing.
    await user.click(create)
    expect(await within(form).findByText('the main rule has protocols but no targets: pick targets, or clear its protocols and use rules only')).toBeDefined()

    // A tag line that is not key=value.
    await user.type(within(form).getByLabelText('By tag'), 'prod')
    await user.click(create)
    expect(await within(form).findByText('tag line "prod" must be key=value')).toBeDefined()
    await user.clear(within(form).getByLabelText('By tag'))
    await user.type(within(form).getByLabelText('By tag'), 'env=prod')

    // Targets with no protocol.
    await user.click(within(form).getByLabelText('SSH'))
    await user.click(create)
    expect(await within(form).findByText('the main rule has targets but no protocol')).toBeDefined()
    await user.click(within(form).getByLabelText('SSH'))

    // Limits that are not whole minutes or days.
    const idle = within(form).getByLabelText('Idle timeout (minutes)')
    await user.clear(idle)
    await user.type(idle, '2.5')
    await user.click(create)
    expect(await within(form).findByText('idle timeout must be a whole number of minutes')).toBeDefined()
    await user.clear(idle)
    await user.type(idle, '30')
    await user.type(within(form).getByLabelText(/Keep recordings/), '4000')
    await user.click(create)
    expect(await within(form).findByText('retention must be 1-3650 days')).toBeDefined()
    await user.clear(within(form).getByLabelText(/Keep recordings/))
    await user.type(within(form).getByLabelText(/Max session/), '0')
    await user.click(create)
    expect(await within(form).findByText('max session must be a whole number of minutes')).toBeDefined()
    await user.clear(within(form).getByLabelText(/Max session/))

    // An extra rule with nothing selected, then one with no protocol.
    await user.click(within(form).getByRole('button', { name: 'Add rule' }))
    await user.click(create)
    expect(await within(form).findByText('rule 1: select targets by tag, by name, or an autoscaling group')).toBeDefined()
    // The rule's pickers repeat the base ones; the second 'fleet' is the rule's.
    await user.click(within(form).getAllByLabelText('fleet')[1])
    await user.click(create)
    expect(await within(form).findByText('rule 1: choose at least one protocol')).toBeDefined()

    expect(post).not.toHaveBeenCalled()
  })

  it('sends what was entered, as the API wants it', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    const { user, form } = await openNew()
    await user.type(within(form).getByLabelText('Name'), '  dba-prod ')
    await user.type(within(form).getByLabelText('Description'), 'Databases, office hours')
    await user.selectOptions(within(form).getByLabelText('Group'), 'g2')
    await user.type(within(form).getByLabelText('By tag'), 'env=prod\n tier = db \n')
    await user.click(within(form).getByLabelText('db-1'))
    await user.click(within(form).getByLabelText('SSH'))
    await user.click(within(form).getByLabelText('database'))
    await user.click(within(form).getByRole('button', { name: 'Add window' }))
    await user.click(within(form).getByLabelText('sat'))
    await user.clear(within(form).getByLabelText('Time zone'))
    const idle = within(form).getByLabelText('Idle timeout (minutes)')
    await user.clear(idle)
    await user.type(idle, '10')
    await user.type(within(form).getByLabelText(/Max session/), '240')
    await user.type(within(form).getByLabelText(/Keep recordings/), '30')
    await user.click(within(form).getByLabelText('Allow file transfer'))
    await user.click(within(form).getByLabelText('Require approval (just-in-time access)'))
    await user.click(within(form).getByRole('button', { name: 'Create' }))

    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(post.mock.calls[0][0]).toBe('/access-policies')
    expect(post.mock.calls[0][1]).toEqual({
      name: 'dba-prod',
      description: 'Databases, office hours',
      enabled: true,
      group_id: 'g2',
      target_selector: { tags: { env: 'prod', tier: 'db' }, targets: ['t2'] },
      protocols: ['database'],
      rules: [],
      time_windows: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat'], from: '09:00', to: '18:00', tz: 'UTC' }],
      idle_timeout_minutes: 10,
      max_session_minutes: 240,
      retention_days: 30,
      allow_clipboard: false,
      allow_file_transfer: true,
      require_mfa: true,
      require_approval: true,
    })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('offers only accounts that can connect as a user policy\'s subject', async () => {
    const { user, form } = await openNew()
    await user.click(within(form).getByLabelText('One user'))
    const picker = within(form).getByLabelText('User') as HTMLSelectElement
    expect(Array.from(picker.options).map((o) => o.textContent)).toEqual(['alice (Alice)'])
    expect(within(form).getByText(/review-only and are not listed/)).toBeDefined()
  })

  it('shows the server\'s refusal in the form and keeps it open', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(refused(422, 'a policy named dba-prod already exists'))
    const { user, form } = await openNew()
    await user.type(within(form).getByLabelText('Name'), 'dba-prod')
    await user.click(within(form).getByLabelText('web-1'))
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    expect(await within(form).findByText('a policy named dba-prod already exists')).toBeDefined()
    expect(screen.getByRole('dialog', { name: 'Add policy' })).toBeDefined()
  })

  it('edits in place and saves with PUT to the policy\'s own address', async () => {
    lists([policy({ rules: [{ target_selector: { targets: ['t1'] }, protocols: ['rdp'] }] })])
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    render(<Policies />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('dialog', { name: 'Edit ops-ssh' })
    expect((within(form).getByLabelText('Name') as HTMLInputElement).value).toBe('ops-ssh')
    expect((within(form).getAllByLabelText('By tag')[0] as HTMLTextAreaElement).value).toBe('env=prod')
    expect((within(form).getAllByLabelText('SSH')[0] as HTMLInputElement).checked).toBe(true)
    // The existing rule is shown with its own pickers, after the base ones.
    expect((within(form).getAllByLabelText('RDP')[0] as HTMLInputElement).checked).toBe(false)
    expect((within(form).getAllByLabelText('RDP')[1] as HTMLInputElement).checked).toBe(true)
    expect((within(form).getAllByLabelText('web-1')[1] as HTMLInputElement).checked).toBe(true)
    await user.click(within(form).getByLabelText('Enabled'))
    await user.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put.mock.calls[0][0]).toBe('/access-policies/p1')
    expect(put.mock.calls[0][1]).toMatchObject({ enabled: false, protocols: ['ssh'], rules: [{ target_selector: { targets: ['t1'] }, protocols: ['rdp'] }] })
  })
})

describe('Deleting a policy', () => {
  it('says who loses access, deletes on confirm, and shows a refusal', async () => {
    lists([policy({ group_id: undefined, user_id: 'u1' })])
    const del = vi.spyOn(api, 'del').mockRejectedValueOnce(refused(409, 'the policy is in use by an approved request')).mockResolvedValue({} as never)
    render(<Policies />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Delete' }))
    const dialog = screen.getByRole('dialog', { name: 'Delete policy ops-ssh?' })
    expect(within(dialog).getByText('alice loses the access it granted, and any live session it allowed ends now.')).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    expect(await within(dialog).findByText('the policy is in use by an approved request')).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(del).toHaveBeenCalledTimes(2))
    expect(del).toHaveBeenLastCalledWith('/access-policies/p1')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })
})
