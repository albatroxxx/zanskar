import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AppsReadiness } from '../../api/types'
import { Applications } from './Applications'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const notReady: AppsReadiness = {
  ready: false,
  checks: [
    { key: 'guacd', title: 'guacd', ok: false, detail: 'set the guacd address' },
    { key: 'runtime', title: 'Container runtime', ok: false, detail: 'the service cannot reach Docker or Podman; add the service user to the docker group' },
    { key: 'image', title: 'Browser image', ok: true, detail: 'ghcr.io/albatroxxx/zanskar-browser:1.7.0' },
  ],
}

function mount(r: AppsReadiness | null) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/applications/readiness') {
      if (!r) throw new Error('no readiness')
      return r as never
    }
    return { items: [] } as never
  })
  render(
    <MemoryRouter>
      <Applications />
    </MemoryRouter>,
  )
}

// An operator who met a prerequisite one refusal at a time (2026-10-27) sees
// the three the isolated browser needs (ADR 0034) with their state before
// trying: the settings link to where they are set, the runtime says what to
// do on the host.
describe('Applications, before the first one', () => {
  it('lists what is done and what is left, with a link to each setting', async () => {
    mount(notReady)
    expect(await screen.findByRole('heading', { name: 'Before the first application' })).toBeDefined()
    const items = screen.getAllByRole('listitem')
    expect(items.map((li) => li.textContent)).toEqual([
      expect.stringContaining('guacd'),
      expect.stringContaining('Container runtime'),
      expect.stringContaining('Browser image'),
    ])
    expect(items[0].textContent).toContain('set the guacd address')
    expect(items[1].textContent).toContain('add the service user to the docker group')
    expect(screen.getByRole('link', { name: 'Settings, Desktops' }).getAttribute('href')).toBe('/admin/settings#settings-desktops')
    // The runtime is fixed on the host, not in a setting: no link.
    expect(screen.getAllByRole('link')).toHaveLength(1)
    expect(screen.getAllByLabelText('to do')).toHaveLength(2)
    expect(screen.getAllByLabelText('done')).toHaveLength(1)
  })

  it('links the browser image to the Applications settings', async () => {
    mount({ ready: false, checks: notReady.checks.map((c) => ({ ...c, ok: c.key !== 'image', detail: c.key === 'image' ? 'set the browser image' : c.detail })) })
    await screen.findByRole('heading', { name: 'Before the first application' })
    expect(screen.getByRole('link', { name: 'Settings, Applications' }).getAttribute('href')).toBe('/admin/settings#settings-applications')
    expect(screen.getAllByRole('link')).toHaveLength(1)
    // Nothing on the page asks for a domain, an address or a certificate any more.
    expect(screen.queryByText(/domain|certificate/i)).toBeNull()
  })

  it('shows nothing of it once the gateway is ready', async () => {
    mount({ ready: true, checks: notReady.checks.map((c) => ({ ...c, ok: true })) })
    expect(await screen.findByText(/No applications yet/)).toBeDefined()
    expect(screen.queryByRole('heading', { name: 'Before the first application' })).toBeNull()
  })

  it('leaves the page usable when the readiness read fails', async () => {
    mount(null)
    expect(await screen.findByText(/No applications yet/)).toBeDefined()
    expect(screen.queryByRole('heading', { name: 'Before the first application' })).toBeNull()
  })
})
