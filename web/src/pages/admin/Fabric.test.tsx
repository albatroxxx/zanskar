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
  vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
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
}

// Fabric (ADR 0048) holds the Kubernetes clusters. Autoscaling groups were
// its first tab for a day and went back to their own page (2026-11-13), so
// the tab's old address leads there.
describe('Fabric', () => {
  it('opens on Kubernetes', async () => {
    at('/admin/fabric')
    expect(await screen.findByRole('heading', { name: 'Fabric' })).toBeDefined()
    expect(screen.getByRole('tab', { name: 'Kubernetes', selected: true })).toBeDefined()
    expect(screen.getByRole('button', { name: 'Add cluster' })).toBeDefined()
  })

  it('sends the old autoscaling tab back to the autoscaling page', async () => {
    at('/admin/fabric/autoscaling')
    expect(await screen.findByRole('heading', { name: 'Autoscaling groups' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/autoscaling')
  })

  it('leads a kind it does not have back to the section', async () => {
    at('/admin/fabric/nothing')
    expect(await screen.findByRole('tab', { name: 'Kubernetes', selected: true })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/fabric')
  })
})
