import { cleanup, render, screen } from '@testing-library/react'
import { Suspense } from 'react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { adminRoutes } from './index'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function Where() {
  return <span data-testid="where">{useLocation().pathname}</span>
}

function at(path: string) {
  const get = vi.spyOn(api, 'get').mockImplementation(async (p: string) =>
    (p === '/admin/overview'
      ? { inventory: { hosts: 0, hosts_by_os: {}, databases: 0, databases_by_engine: {}, applications: 0, clusters: 3, clusters_by_platform: { vanilla: 2, eks: 1 } } }
      : { items: [] }) as never,
  )
  render(
    <MemoryRouter initialEntries={[path]}>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/admin">{adminRoutes}</Route>
        </Routes>
      </Suspense>
      <Where />
    </MemoryRouter>,
  )
  return get
}

// Fabric (ADR 0048) holds the Kubernetes clusters, a tab per platform: all
// four are Kubernetes, so the first is Vanilla. A tile per platform above
// the tabs counts its clusters and opens its tab; nothing filters, each
// tab lists its own. Autoscaling groups were the first tab for a day and
// went back to their own page (2026-11-13), so that address leads there.
describe('Fabric', () => {
  it('opens on Vanilla, listing only its clusters', async () => {
    const get = at('/admin/fabric')
    expect(await screen.findByRole('heading', { name: 'Kubernetes' })).toBeDefined()
    expect(screen.getByRole('tab', { name: 'Vanilla', selected: true })).toBeDefined()
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['Vanilla', 'EKS', 'GKE', 'AKS'])
    expect(screen.getByRole('button', { name: 'Add cluster' })).toBeDefined()
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=kubernetes&platform=vanilla')
    expect(screen.queryByRole('button', { name: /remove filter/ })).toBeNull()
  })

  it('shows a tile per platform, counting its clusters and opening its tab', async () => {
    const get = at('/admin/fabric')
    const tiles = await screen.findAllByRole('link', { name: /Vanilla|EKS|GKE|AKS/ })
    expect(tiles.map((a) => a.textContent)).toEqual(['2Vanilla', '1EKS', '0GKE', '0AKS'])
    expect(tiles.map((a) => a.getAttribute('href'))).toEqual(['/admin/fabric/vanilla', '/admin/fabric/eks', '/admin/fabric/gke', '/admin/fabric/aks'])
    tiles[1].click()
    expect(await screen.findByRole('tab', { name: 'EKS', selected: true })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/fabric/eks')
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=kubernetes&platform=eks')
  })

  it('sends the old autoscaling tab back to the autoscaling page', async () => {
    at('/admin/fabric/autoscaling')
    expect(await screen.findByRole('heading', { name: 'Autoscaling groups' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/autoscaling')
  })

  it('leads an address it does not have back to the section', async () => {
    at('/admin/fabric/nothing')
    expect(await screen.findByRole('tab', { name: 'Vanilla', selected: true })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/fabric')
  })
})
