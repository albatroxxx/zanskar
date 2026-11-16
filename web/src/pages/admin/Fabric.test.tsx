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
// The section read /admin/fabric until 2.0.0 and /admin/kubernetes since
// (2026-11-16); the old address, with or without a tab, leads to the new.
describe('Fabric', () => {
  it('opens on Vanilla, listing only its clusters', async () => {
    const get = at('/admin/kubernetes')
    expect(await screen.findByRole('heading', { name: 'Kubernetes' })).toBeDefined()
    // The tiles are the tabs: the open one says so, and there is no tab row beneath.
    expect(await screen.findByRole('link', { name: /Vanilla/, current: 'page' })).toBeDefined()
    expect(screen.queryByRole('tablist')).toBeNull()
    expect(screen.getByRole('button', { name: 'Add cluster' })).toBeDefined()
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=kubernetes&platform=vanilla')
    expect(screen.queryByRole('button', { name: /remove filter/ })).toBeNull()
  })

  it('shows a tile per platform, counting its clusters and opening its tab', async () => {
    const get = at('/admin/kubernetes')
    const tiles = await screen.findAllByRole('link', { name: /Vanilla|EKS|GKE|AKS/ })
    expect(tiles.map((a) => a.textContent)).toEqual(['2Vanilla', '1EKS', '0GKE', '0AKS'])
    expect(tiles.map((a) => a.getAttribute('href'))).toEqual(['/admin/kubernetes/vanilla', '/admin/kubernetes/eks', '/admin/kubernetes/gke', '/admin/kubernetes/aks'])
    // The open platform's tile is the selected one, and says so.
    expect(tiles[0].getAttribute('aria-current')).toBe('page')
    expect(tiles[1].getAttribute('aria-current')).toBeNull()
    tiles[1].click()
    await screen.findByRole('link', { name: /EKS/, current: 'page' })
    expect(tiles[1].getAttribute('aria-current')).toBe('page')
    expect(tiles[0].getAttribute('aria-current')).toBeNull()
    expect(screen.getByTestId('where').textContent).toBe('/admin/kubernetes/eks')
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=kubernetes&platform=eks')
  })

  it('sends the old autoscaling tab back to the autoscaling page', async () => {
    at('/admin/kubernetes/autoscaling')
    expect(await screen.findByRole('heading', { name: 'Autoscaling groups' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/autoscaling')
  })

  it('leads the section\'s old address to the new one', async () => {
    at('/admin/fabric')
    expect(await screen.findByRole('link', { name: /Vanilla/, current: 'page' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/kubernetes')
  })

  it('leads an old tab address to the same tab at the new address', async () => {
    const get = at('/admin/fabric/eks')
    expect(await screen.findByRole('link', { name: /EKS/, current: 'page' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/kubernetes/eks')
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=kubernetes&platform=eks')
  })

  it('leads the old autoscaling tab address through to the autoscaling page', async () => {
    at('/admin/fabric/autoscaling')
    expect(await screen.findByRole('heading', { name: 'Autoscaling groups' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/autoscaling')
  })

  it('leads an address it does not have back to the section', async () => {
    at('/admin/kubernetes/nothing')
    expect(await screen.findByRole('link', { name: /Vanilla/, current: 'page' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/kubernetes')
  })
})
