import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { credentialTypeName } from '../../api/format'
import type { Credential, KubeTest, Target } from '../../api/types'
import { Fabric } from './Fabric'
import { TargetDetail } from './TargetDetail'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const cluster: Target = {
  id: 'k1', name: 'prod', address: 'k8s.example', os_family: 'other', kube_api_server: 'https://k8s.example:6443', kube_impersonate: true,
  ports: {}, capabilities: ['kube', 'pod'], host_key_fingerprint: null, host_key_status: 'unknown', tls_fingerprint: null, winrm_tls_fingerprint: null,
  tags: { env: 'prod' }, status: 'active', state: 'active', tls_status: 'none', winrm_tls_status: 'none', notes: '', credentials: { kube: 'c1' },
  created_at: '2026-11-12T10:00:00Z', updated_at: '2026-11-12T10:00:00Z', last_probed_at: null,
}
const sa: Credential = { id: 'c1', name: 'prod-sa', type: 'kube_token', mode: 'vaulted', has_secret: true, created_at: '', updated_at: '' }

function serve(targets: Target[]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.startsWith('/credentials') ? [sa] : targets }) as never)
}

// A Kubernetes cluster (ADR 0045) lives on Fabric's tab for its platform
// (ADR 0048): listed by its API server and who its sessions act as, added
// as a cluster of that platform, and tested against the cluster from its
// drawer, where the RBAC it needs is printed.
describe('Kubernetes', () => {
  it('lists a platform\'s clusters under its tab and adds one of that platform', async () => {
    const get = serve([cluster])
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ...cluster, id: 'k2', name: 'staging' } as never)
    render(
      <MemoryRouter initialEntries={['/admin/fabric/gke']}>
        <Routes>
          <Route path="/admin/fabric/:kind" element={<Fabric />} />
        </Routes>
      </MemoryRouter>,
    )
    expect(await screen.findByRole('tab', { name: 'GKE', selected: true })).toBeDefined()
    const row = (await screen.findByText('prod-sa')).closest('tr')!
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=kubernetes&platform=gke')
    expect(within(row).getByText('https://k8s.example:6443')).toBeDefined()
    expect(within(row).getByText('the person')).toBeDefined()
    // No platform column: the tab says it.
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'API server', 'Acts as', 'Credential', 'Tags', 'Actions'])
    // One head: Fabric's, with its Add button; the tab's page shows none of its own.
    expect(screen.getAllByRole('heading', { level: 1 }).map((h) => h.textContent)).toEqual(['Fabric'])

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Add cluster' }))
    const form = screen.getByRole('dialog', { name: 'Add cluster' })
    // The tab's platform, chosen already.
    expect((within(form).getByLabelText('Platform') as HTMLSelectElement).value).toBe('gke')
    await user.type(within(form).getByLabelText('Name'), 'staging')
    await user.type(within(form).getByLabelText('API server'), 'https://staging.example:6443')
    await user.selectOptions(within(form).getByLabelText('Sessions act as'), 'credential')
    await user.type(within(form).getByLabelText('CA bundle (PEM)'), '-----BEGIN CERTIFICATE-----')
    await user.click(within(form).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(post).toHaveBeenCalled())
    const body = post.mock.calls[0][1] as Record<string, unknown>
    expect(body).toMatchObject({ name: 'staging', address: '', os_family: 'other', kube_api_server: 'https://staging.example:6443', kube_ca: '-----BEGIN CERTIFICATE-----', kube_impersonate: false, kube_platform: 'gke', engine: '', app_upstream: '' })
  })

  it('tests the cluster from its drawer and prints the RBAC manifest', async () => {
    const result: KubeTest = { version: 'v1.31.1', impersonate_users: true, impersonate_groups: false, namespaces: ['prod', 'ops'], namespaces_listed: true }
    const post = vi.spyOn(api, 'post').mockResolvedValue(result as never)
    const text = vi.spyOn(api, 'text').mockResolvedValue('kind: ClusterRole\n' as never)
    render(<TargetDetail target={cluster} credentials={[sa]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)
    expect(screen.getByText('https://k8s.example:6443')).toBeDefined()
    expect(screen.queryByText('Host key')).toBeNull()

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/targets/k1/kube/test'))
    expect(await screen.findByText('v1.31.1')).toBeDefined()
    expect(screen.getByText('users only')).toBeDefined()
    expect(screen.getByText('prod, ops')).toBeDefined()

    await user.click(screen.getByRole('button', { name: 'RBAC manifest' }))
    await waitFor(() => expect(text).toHaveBeenCalledWith('/targets/k1/kube/manifest'))
    const dialog = await screen.findByRole('dialog', { name: 'RBAC manifest' })
    expect(within(dialog).getByText(/kind: ClusterRole/)).toBeDefined()
  })

  it('says a shared identity where the sessions act as the credential', () => {
    render(<TargetDetail target={{ ...cluster, kube_impersonate: false }} credentials={[sa]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)
    expect(screen.getByText('the credential (shared identity)')).toBeDefined()
  })

  it('names the two credential types', () => {
    expect(credentialTypeName('kube_token')).toBe('Kubernetes service account token')
    expect(credentialTypeName('kube_client_cert')).toBe('Kubernetes client certificate')
  })
})
