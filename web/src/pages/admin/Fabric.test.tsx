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

// Fabric (ADR 0048) holds what Zanskar reaches through a control plane; the
// autoscaling groups are its first tab, and their old address leads there.
describe('Fabric', () => {
  it('opens on the Autoscaling tab, where the old address leads', async () => {
    at('/admin/autoscaling')
    expect(await screen.findByRole('heading', { name: 'Fabric' })).toBeDefined()
    expect(screen.getByRole('tab', { name: 'Autoscaling', selected: true })).toBeDefined()
    expect(screen.getByRole('button', { name: 'Enroll group' })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/fabric/autoscaling')
  })

  it('leads a kind it does not have back to the section', async () => {
    at('/admin/fabric/nothing')
    expect(await screen.findByRole('tab', { name: 'Autoscaling', selected: true })).toBeDefined()
    expect(screen.getByTestId('where').textContent).toBe('/admin/fabric')
  })
})
