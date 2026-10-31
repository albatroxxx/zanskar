import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { Policy, PolicyGrant } from '../../api/types'
import { Policies } from './Policies'
import { PolicyEditor } from './PolicyEditor'
import { newGrant } from './policyModel'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// ADR 0036: a policy names many groups and users and holds grants, each
// picking a kind, then targets with a protocol each or tags, then its own
// conditions. The list shows one line per grant; the editor is a page.

const groups = [{ id: 'g1', name: 'ops', member_count: 2 }, { id: 'g2', name: 'dba', member_count: 1 }]
const users = [
  { id: 'u1', username: 'alice', display_name: 'Alice', roles: ['user'], status: 'active' },
  { id: 'u2', username: 'ava', display_name: 'Ava the auditor', roles: ['auditor'], status: 'active' },
]
const targets = [
  { id: 't1', name: 'web-1', os_family: 'linux', capabilities: ['ssh'], status: 'active', tags: { env: 'prod' } },
  { id: 't2', name: 'dc-1', os_family: 'windows', capabilities: [], status: 'active', tags: { env: 'prod' } },
  { id: 't3', name: 'build', os_family: 'linux', capabilities: [], status: 'active', tags: { env: 'staging' } },
  { id: 'd1', name: 'orders', os_family: 'other', engine: 'postgres', capabilities: [], status: 'active', tags: {} },
  { id: 'w1', name: 'wiki', os_family: 'other', app_upstream: 'http://10.0.0.8', capabilities: [], status: 'active', tags: {} },
]
const asgs = [{ id: 'a1', name: 'fleet', os_family: 'linux', capabilities: ['ssh'], tags: {} }]

function grant(over: Partial<PolicyGrant>): PolicyGrant {
  return { ...newGrant('host'), id: 'gr1', ...over }
}

function policy(over: Partial<Policy> = {}): Policy {
  return {
    id: 'p1', name: 'ops-web', description: 'Shell on the fleet', enabled: true,
    subjects: [{ kind: 'group', id: 'g1' }],
    grants: [grant({ targets: [{ id: 't1', protocols: ['ssh'] }] })],
    created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', ...over,
  }
}

/** serve answers every collection the pages read, and the one policy by id. */
function serve(policies: Policy[]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    const one = policies.find((p) => path === `/access-policies/${p.id}`)
    if (one) return one as never
    const items = path.startsWith('/access-policies') ? policies : path.startsWith('/groups') ? groups : path.startsWith('/users') ? users
      : path.startsWith('/targets') ? targets : path.startsWith('/autoscaling-groups') ? asgs : []
    return { items } as never
  })
}

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>
}

function at(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/admin/policies" element={<><Policies /><Where /></>} />
        <Route path="/admin/policies/new" element={<><PolicyEditor /><Where /></>} />
        <Route path="/admin/policies/:id" element={<><PolicyEditor /><Where /></>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('the policy list', () => {
  // ADR 0036, amended 2026-10-30: a rollup and the loosest terms in the
  // row; the grants side by side when it opens.
  it('sums each policy up, flags standing access without MFA, and opens to its grants', async () => {
    serve([
      policy({ grants: [grant({ targets: [{ id: 't1', protocols: ['ssh'] }, { id: 't2', protocols: ['rdp', 'winrm'] }] }),
        grant({ id: 'gr2', kind: 'database', targets: [{ id: 'd1', protocols: ['database'] }], access: 'approval', require_mfa: false })] }),
      policy({ id: 'p2', name: 'orphan', description: '', subjects: [], enabled: false, grants: [grant({ targets: [{ id: 't3', protocols: ['ssh'] }], require_mfa: false })] }),
    ])
    at('/admin/policies')
    const user = userEvent.setup()
    const first = (await screen.findByText('ops-web')).closest('tr')!
    expect(within(first).getByText('ops')).toBeDefined()
    const toggle = within(first).getByRole('button', { name: /2 grants · Host 1 · Database 1/ })
    expect(toggle.textContent).toContain('3 targets')
    expect(within(first).getByText('Standing ×1 · Approval ×1')).toBeDefined()
    expect(within(first).getByText('no MFA ×1')).toBeDefined()
    expect(within(first).queryByText(/standing, no MFA/)).toBeNull()
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    await user.click(toggle)
    expect(toggle.getAttribute('aria-expanded')).toBe('true')
    const grants = screen.getByRole('table', { name: 'Grants of ops-web' })
    expect(within(grants).getByText('web-1 (SSH), dc-1 (RDP, WinRM)')).toBeDefined()
    expect(within(grants).getAllByRole('row')).toHaveLength(3)
    await user.click(toggle)
    expect(screen.queryByRole('table', { name: 'Grants of ops-web' })).toBeNull()

    const orphan = screen.getByText('orphan').closest('tr')!
    expect(within(orphan).getByText('no one')).toBeDefined()
    expect(within(orphan).getByText('standing, no MFA')).toBeDefined()
    expect(within(orphan).getByRole('button', { name: 'Disabled' })).toBeDefined()
    expect(within(first).getByRole('link', { name: 'Edit' }).getAttribute('href')).toBe('/admin/policies/p1')
  })

  it('counts a target no list holds as not found, never as an id', async () => {
    serve([policy({ grants: [grant({ targets: [{ id: 't1', protocols: ['ssh'] }, { id: 'gone-1234567', protocols: ['ssh'] }] })] })])
    at('/admin/policies')
    const row = (await screen.findByText('ops-web')).closest('tr')!
    expect(await within(row).findByText('1 not found')).toBeDefined()
    await userEvent.setup().click(within(row).getByRole('button', { name: /1 grant/ }))
    expect(screen.getByText('web-1 (SSH), not found (SSH)')).toBeDefined()
    expect(screen.queryByText(/gone-123/)).toBeNull()
  })

  it('deletes after a confirmation that says what happens to live sessions', async () => {
    serve([policy()])
    const del = vi.spyOn(api, 'del').mockResolvedValue(undefined as never)
    at('/admin/policies')
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Delete' }))
    const dialog = screen.getByRole('dialog', { name: 'Delete policy ops-web?' })
    expect(within(dialog).getByText(/re-checked/)).toBeDefined()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/access-policies/p1'))
  })
})

describe('the policy editor', () => {
  it('builds a policy for groups and users, with a protocol per target, tags, and conditions per grant', async () => {
    serve([])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    at('/admin/policies/new')
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Name'), 'platform')
    // Many groups and users; a review-only account is not offered.
    await user.click(await screen.findByLabelText('ops'))
    await user.click(screen.getByLabelText('dba'))
    expect(screen.queryByLabelText('ava')).toBeNull()
    await user.click(screen.getByLabelText('alice'))

    // Host is the first kind: only hosts are listed, each with the
    // protocols it serves; a host with one is ticked for the admin.
    const card = screen.getByRole('region', { name: 'Grant 1' })
    expect(within(card).queryByLabelText('orders')).toBeNull()
    expect(within(card).queryByLabelText('Developer tools')).toBeNull() // applications only (ADR 0037)
    await user.click(within(card).getByLabelText('web-1'))
    expect((within(card).getByLabelText('SSH on web-1') as HTMLInputElement).checked).toBe(true)
    await user.click(within(card).getByLabelText('dc-1'))
    expect(within(card).getByLabelText('RDP on dc-1')).toBeDefined()
    expect(within(card).queryByLabelText('VNC on dc-1')).toBeNull() // a Windows host before a probe: rdp, winrm, ssh
    await user.click(within(card).getByLabelText('RDP on dc-1'))
    await user.click(within(card).getByLabelText('WinRM on dc-1'))
    // Tags: every key, any of a repeated key's values.
    await user.click(within(card).getByRole('button', { name: 'Add tag' }))
    await user.type(within(card).getByLabelText('Tag 1 key'), 'env')
    await user.type(within(card).getByLabelText('Tag 1 value'), 'staging')
    await user.click(within(card).getByRole('radio', { name: 'Approval (just-in-time)' }))
    await user.click(within(card).getByLabelText('Clipboard'))

    // A second grant with the same conditions, for the database.
    await user.click(screen.getByRole('button', { name: 'Add grant, same conditions' }))
    const second = screen.getByRole('region', { name: 'Grant 2' })
    await user.click(within(second).getByRole('radio', { name: 'Database' }))
    await user.click(within(second).getByLabelText('orders'))
    expect(within(second).queryByLabelText(/on orders/)).toBeNull() // a database has one protocol, not chips
    await user.click(screen.getByRole('button', { name: 'Create' }))

    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    const [path, body] = post.mock.calls[0] as [string, Record<string, unknown>]
    expect(path).toBe('/access-policies')
    expect(body).toEqual({
      name: 'platform', description: '', enabled: true,
      subjects: [{ kind: 'group', id: 'g1' }, { kind: 'group', id: 'g2' }, { kind: 'user', id: 'u1' }],
      grants: [
        { kind: 'host', targets: [{ id: 't1', protocols: ['ssh'] }, { id: 't2', protocols: ['rdp', 'winrm'] }],
          tags: { match: { env: ['staging'] }, protocols: ['ssh'] }, access: 'approval', sign_in: 'target', require_mfa: true,
          allow_clipboard: true, allow_file_transfer: false, idle_timeout_minutes: 15, max_session_minutes: null, time_windows: [], retention_days: null },
        { kind: 'database', targets: [{ id: 'd1', protocols: ['database'] }], access: 'approval', sign_in: 'target', require_mfa: true,
          allow_clipboard: true, allow_file_transfer: false, idle_timeout_minutes: 15, max_session_minutes: null, time_windows: [], retention_days: null },
      ],
    })
    expect(screen.getByTestId('where').textContent).toBe('/admin/policies')
    // Nothing of the old shape goes out.
    for (const old of ['group_id', 'user_id', 'target_selector', 'protocols', 'rules', 'require_approval']) expect(body).not.toHaveProperty(old)
  })

  it('offers developer tools on an application grant only', async () => {
    serve([])
    at('/admin/policies/new')
    const user = userEvent.setup()
    const card = await screen.findByRole('region', { name: 'Grant 1' })
    expect(within(card).queryByLabelText('Developer tools')).toBeNull()
    await user.click(within(card).getByRole('radio', { name: 'Application' }))
    const box = within(card).getByLabelText('Developer tools') as HTMLInputElement
    expect(box.checked).toBe(false)
    await user.click(box)
    expect(box.checked).toBe(true)
  })

  it('names what is missing before sending, and the server\'s refusal after', async () => {
    serve([])
    const post = vi.spyOn(api, 'post').mockRejectedValue(new ApiError(422, { code: 'kind_mismatch', message: 'grant 1: t1 is a database, not a host', request_id: 'r' }, '422'))
    at('/admin/policies/new')
    const user = userEvent.setup()
    await user.type(await screen.findByLabelText('Name'), 'p')
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('Choose at least one group or user')).toBeDefined()
    await user.click(await screen.findByLabelText('ops'))
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('Grant 1: choose targets, or match tags')).toBeDefined()
    const card = screen.getByRole('region', { name: 'Grant 1' })
    await user.click(within(card).getByLabelText('build')) // two protocols possible: none ticked
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('Grant 1: build has no protocol')).toBeDefined()
    expect(post).not.toHaveBeenCalled()
    await user.click(within(card).getByLabelText('SSH on build'))
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('grant 1: t1 is a database, not a host')).toBeDefined()
  })

  it('edits in place: loads the grants, keeps their ids, and saves with PUT', async () => {
    serve([policy({ grants: [grant({ targets: [{ id: 't1', protocols: ['ssh'] }] })] })])
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    at('/admin/policies/p1')
    const user = userEvent.setup()
    expect(((await screen.findByLabelText('Name')) as HTMLInputElement).value).toBe('ops-web')
    expect((screen.getByLabelText('ops') as HTMLInputElement).checked).toBe(true)
    const card = screen.getByRole('region', { name: 'Grant 1' })
    expect((within(card).getByLabelText('SSH on web-1') as HTMLInputElement).checked).toBe(true)
    // Changing the kind resets what the grant covered.
    await user.click(within(card).getByRole('radio', { name: 'Autoscaling' }))
    await user.click(within(card).getByLabelText('fleet'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [path, body] = put.mock.calls[0] as [string, { grants: PolicyGrant[] }]
    expect(path).toBe('/access-policies/p1')
    expect(body.grants).toHaveLength(1)
    expect(body.grants[0]).toMatchObject({ id: 'gr1', kind: 'autoscaling', targets: [{ id: 'a1', protocols: ['ssh'] }] })
  })

  // 2026-10-30: WinRM was missing from a Windows host with no word of why,
  // and a converted 1.7 policy kept RDP on a Linux box. A probed host shows
  // its usual protocols the probe did not find greyed, and a chosen one it
  // did not find in warning, so it can be unticked.
  it('greys the usual protocols a probe did not find and flags a chosen one it did not', async () => {
    serve([policy({ grants: [grant({ targets: [{ id: 't1', protocols: ['ssh', 'rdp'] }, { id: 't2', protocols: ['rdp'] }] })] })])
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    at('/admin/policies/p1')
    const user = userEvent.setup()
    const card = await screen.findByRole('region', { name: 'Grant 1' })
    // web-1 (Linux, probed: ssh): VNC is usual but was not found.
    const vnc = within(card).getByLabelText('VNC on web-1, not found by the last probe; probe again') as HTMLInputElement
    expect(vnc.disabled).toBe(true)
    const rdp = within(card).getByLabelText('RDP on web-1, not found by the last probe') as HTMLInputElement
    expect(rdp.checked).toBe(true)
    expect(rdp.closest('.chip-toggle')?.className).toContain('stale')
    // dc-1 (Windows, never probed): what Windows usually serves, nothing greyed.
    expect(within(card).getByLabelText('WinRM on dc-1')).toBeDefined()
    expect(within(card).queryByLabelText(/on dc-1, not found/)).toBeNull()
    await user.click(rdp)
    expect(within(card).queryByLabelText('RDP on web-1, not found by the last probe')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, body] = put.mock.calls[0] as [string, { grants: PolicyGrant[] }]
    expect(body.grants[0].targets).toEqual([{ id: 't1', protocols: ['ssh'] }, { id: 't2', protocols: ['rdp'] }])
  })

  it('selects every host at once and sets a protocol on all of them', async () => {
    serve([policy({ grants: [grant({ targets: [] })] })])
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    at('/admin/policies/p1')
    const user = userEvent.setup()
    const card = await screen.findByRole('region', { name: 'Grant 1' })
    await user.click(within(card).getByLabelText('Select all hosts'))
    expect(within(card).getByText('3 of 3 chosen')).toBeDefined()
    const bulk = within(card).getByRole('group', { name: 'Grant 1 protocols for every chosen target' })
    await user.click(within(bulk).getByLabelText('SSH'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, body] = put.mock.calls[0] as [string, { grants: PolicyGrant[] }]
    // web-1 had SSH picked for it (its one protocol); dc-1 and build gain it.
    expect(body.grants[0].targets).toEqual([
      { id: 't1', protocols: ['ssh'] },
      { id: 't2', protocols: ['ssh'] },
      { id: 't3', protocols: ['ssh'] },
    ])
  })

  it('shows a target the grant names that no list holds, so it can be removed', async () => {
    serve([policy({ grants: [grant({ targets: [{ id: 't1', protocols: ['ssh'] }, { id: 'gone-1', protocols: ['ssh'] }] })] })])
    const put = vi.spyOn(api, 'put').mockResolvedValue({} as never)
    at('/admin/policies/p1')
    const user = userEvent.setup()
    const card = await screen.findByRole('region', { name: 'Grant 1' })
    const gone = within(card).getByLabelText('gone-1') as HTMLInputElement
    expect(gone.checked).toBe(true)
    expect(within(card).getByText('not found')).toBeDefined()
    await user.click(gone)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    const [, body] = put.mock.calls[0] as [string, { grants: PolicyGrant[] }]
    expect(body.grants[0].targets).toEqual([{ id: 't1', protocols: ['ssh'] }])
  })
})
