import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Suspense } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { CloudSetup, CloudTest, Target } from '../../api/types'
import { adminRoutes } from './index'
import { TargetDetail } from './TargetDetail'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const base = {
  address: '', os_family: 'other' as const, ports: {}, capabilities: ['cloud' as const], host_key_fingerprint: null, host_key_status: 'unknown' as const,
  tls_fingerprint: null, winrm_tls_fingerprint: null, status: 'active' as const, state: 'active' as const, tls_status: 'none' as const, winrm_tls_status: 'none' as const,
  notes: '', credentials: {}, created_at: '2026-11-16T10:00:00Z', updated_at: '2026-11-16T10:00:00Z', last_probed_at: null,
  cloud_platform: 'aws' as const, cloud_external_id: 'zanskar-0123456789abcdef0123456789abcdef',
}
const prodAdmin: Target = { ...base, id: 'c1', name: 'prod-admin', cloud_account_id: '111111111111', cloud_account_alias: 'prod', cloud_role_arn: 'arn:aws:iam::111111111111:role/Admin', cloud_max_minutes: 60, cloud_region: 'eu-west-1', tags: { env: 'prod' } }
const prodRead: Target = { ...base, id: 'c2', name: 'prod-read', cloud_account_id: '111111111111', cloud_account_alias: 'prod', cloud_role_arn: 'arn:aws:iam::111111111111:role/ReadOnly', cloud_max_minutes: 480, cloud_region: '', tags: {} }
const devAdmin: Target = { ...base, id: 'c3', name: 'dev-admin', cloud_account_id: '222222222222', cloud_role_arn: 'arn:aws:iam::222222222222:role/Admin', cloud_max_minutes: 60, cloud_region: 'us-east-1', tags: {} }

function serve(targets: Target[]) {
  return vi.spyOn(api, 'get').mockImplementation(async (p: string) => {
    if (p === '/admin/overview') return { inventory: { hosts: 0, hosts_by_os: {}, databases: 0, databases_by_engine: {}, applications: 0, clusters: 0, clusters_by_platform: {}, cloud_roles: 3, cloud_accounts: 2 } } as never
    if (p.startsWith('/credentials')) return { items: [] } as never
    return { items: targets } as never
  })
}

function page(path = '/admin/cloud') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/admin">{adminRoutes}</Route>
        </Routes>
      </Suspense>
    </MemoryRouter>,
  )
}

const drawer = (t: Target) => render(<TargetDetail target={t} credentials={[]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)

// Cloud accounts (ADR 0050): a role in an AWS account is a target. The
// section shows one tile, AWS, counting roles and accounts, then the roles
// under their accounts; a role is added with its account, ARN and minutes,
// its trust pastes come from Setup, and Test assumes it.
describe('Cloud accounts', () => {
  it('counts on one tile and lists the roles under their accounts', async () => {
    const get = serve([devAdmin, prodAdmin, prodRead])
    page()
    expect(await screen.findByRole('heading', { name: 'Cloud accounts' })).toBeDefined()
    const tile = await screen.findByRole('link', { name: /AWS/, current: 'page' })
    expect(tile.textContent).toBe('3AWS2 accounts')
    // One platform tile: no GCP, no Azure, nothing to fill a row.
    expect(screen.getAllByRole('link', { name: /AWS|GCP|Azure/ })).toHaveLength(1)
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=cloud')
    await screen.findByText('prod-admin')
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'Role', 'Max', 'Region', 'Tags', 'Actions', '222222222222', 'prod · 111111111111'])
    const rows = screen.getAllByRole('row').map((r) => r.textContent)
    // The header rows group the roles, accounts as they read (digits before letters), each account's roles by name.
    const order = rows.filter((r) => /prod · 111111111111|222222222222|prod-admin|prod-read|dev-admin/.test(r ?? ''))
    expect(order.map((r) => (r ?? '').startsWith('prod · ') ? 'prod' : (r ?? '').startsWith('222') ? 'dev' : r?.match(/^(prod-admin|prod-read|dev-admin)/)?.[1])).toEqual(['dev', 'dev-admin', 'prod', 'prod-admin', 'prod-read'])
    const row = screen.getByText('prod-admin').closest('tr')!
    expect(within(row).getByText('Admin')).toBeDefined()
    expect(within(row).getByText('60 min')).toBeDefined()
    expect(within(row).getByText('eu-west-1')).toBeDefined()
  })

  it('adds a role with its account, ARN, minutes and region', async () => {
    serve([])
    const post = vi.spyOn(api, 'post').mockResolvedValue(prodAdmin as never)
    page()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Add role' }))
    const form = screen.getByRole('dialog', { name: 'Add role' })
    // No host fields, no credential, no retention: the role is the account, the ARN and the minutes.
    expect(within(form).queryByLabelText('Operating system')).toBeNull()
    expect(within(form).queryByLabelText(/Recording retention/)).toBeNull()
    expect((within(form).getByLabelText('Max (minutes)') as HTMLInputElement).value).toBe('60')
    await user.type(within(form).getByLabelText('Name'), 'prod-admin')
    await user.type(within(form).getByLabelText('Account ID'), '111111111111')
    await user.type(within(form).getByLabelText('Alias'), 'prod')
    await user.type(within(form).getByLabelText('Role ARN'), 'arn:aws:iam::222222222222:role/Admin')
    await user.type(within(form).getByLabelText('Region'), 'eu-west-1')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    // The ARN names another account: refused here, nothing sent.
    expect(await within(form).findByText('role ARN is in another account')).toBeDefined()
    expect(post).not.toHaveBeenCalled()
    await user.clear(within(form).getByLabelText('Role ARN'))
    await user.type(within(form).getByLabelText('Role ARN'), 'arn:aws:iam::111111111111:role/Admin')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalled())
    expect(post.mock.calls[0][0]).toBe('/targets')
    expect(post.mock.calls[0][1]).toMatchObject({
      name: 'prod-admin', address: '', os_family: 'other', engine: '', app_upstream: '', kube_api_server: '',
      cloud_platform: 'aws', cloud_account_id: '111111111111', cloud_account_alias: 'prod', cloud_role_arn: 'arn:aws:iam::111111111111:role/Admin',
      cloud_external_id: '', cloud_max_minutes: 60, cloud_region: 'eu-west-1', retention_days: null,
    })
  })

  it('shows the role without a credential slot, and prints the pastes once the principal is known', async () => {
    const pending: CloudSetup = { principal: null, pending: true, external_id: prodAdmin.cloud_external_id!, trust_policy: '', permissions_policy: '{"Action":"cloudtrail:LookupEvents"}', cli: '', cloudformation: '' }
    const ready: CloudSetup = { ...pending, principal: 'arn:aws:iam::999999999999:role/Zanskar-Gateway-Role', pending: false, trust_policy: '{"Version":"2012-10-17"}', cli: 'aws iam create-role', cloudformation: 'AWSTemplateFormatVersion' }
    const get = vi.spyOn(api, 'get').mockResolvedValueOnce(pending as never).mockResolvedValueOnce(ready as never)
    drawer(prodAdmin)
    expect(screen.getByText('prod · 111111111111')).toBeDefined()
    expect(screen.getByText('Admin')).toBeDefined()
    expect(screen.getByText(prodAdmin.cloud_external_id!)).toBeDefined()
    expect(screen.queryByText(/Credentials per protocol|Cluster credential/)).toBeNull()
    expect(screen.queryByRole('button', { name: 'Probe' })).toBeNull()

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Setup' }))
    await waitFor(() => expect(get).toHaveBeenCalledWith('/targets/c1/cloud/setup'))
    const dialog = await screen.findByRole('dialog', { name: 'prod-admin: setup' })
    expect(await within(dialog).findByText("The gateway's AWS principal is not known yet.")).toBeDefined()
    expect(within(dialog).queryByRole('button', { name: 'Copy trust policy' })).toBeNull()
    await user.click(within(dialog).getByRole('button', { name: 'Check again' }))
    expect(await within(dialog).findByText('{"Version":"2012-10-17"}')).toBeDefined()
    expect(within(dialog).getByText('arn:aws:iam::999999999999:role/Zanskar-Gateway-Role')).toBeDefined()
    expect(within(dialog).getByRole('button', { name: 'Copy trust policy' })).toBeDefined()
    // The activity policy (phase C) sits under the trust policy, with its one-clause consequence.
    expect(within(dialog).getAllByRole('heading', { level: 3 }).map((h) => h.textContent)).toEqual(['1 · Trust policy', '2 · Activity policy', '3 · Put both on the role', '4 · CloudFormation'])
    expect(within(dialog).getByText('{"Action":"cloudtrail:LookupEvents"}')).toBeDefined()
    expect(within(dialog).getByText('Without it, Activity is not read.')).toBeDefined()
    expect(within(dialog).getByRole('button', { name: 'Copy activity policy' })).toBeDefined()
    expect(within(dialog).getByRole('button', { name: 'Copy CLI' })).toBeDefined()
    expect(within(dialog).getByRole('button', { name: 'Copy CloudFormation' })).toBeDefined()
  })

  it('tests the role and names the stage that refused', async () => {
    const ok: CloudTest = { ok: true, assumed_arn: 'arn:aws:sts::111111111111:assumed-role/Admin/zanskar-test', stage: '', message: '', lookup_events: false }
    const refused: CloudTest = { ok: false, stage: 'assume', message: 'the trust policy does not name this gateway', lookup_events: null }
    const post = vi.spyOn(api, 'post').mockResolvedValueOnce(ok as never).mockResolvedValueOnce(refused as never)
    drawer(prodAdmin)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/targets/c1/cloud/test', {}))
    expect(await screen.findByText('arn:aws:sts::111111111111:assumed-role/Admin/zanskar-test')).toBeDefined()
    expect(screen.getByText(/activity not readable/)).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Test' }))
    expect(await screen.findByText('Not assumed: the trust policy does not name this gateway')).toBeDefined()
  })
})
