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
    { key: 'domain', title: 'Apps domain', ok: false, detail: 'set the apps domain in Settings' },
    { key: 'public_url', title: 'Public address', ok: true, detail: 'the console is reached at https://gw.example.com' },
    { key: 'certificate', title: 'Certificate for the apps domain', ok: false, detail: 'waits for the apps domain' },
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

// An operator who meets "set the apps domain first" one refusal at a time
// (2026-10-27) now sees the three prerequisites with their state before
// trying, each pointing at where it is set.
describe('Applications, before the first one', () => {
  it('lists what is done and what is left, with a link to each setting', async () => {
    mount(notReady)
    expect(await screen.findByRole('heading', { name: 'Before the first application' })).toBeDefined()
    const items = screen.getAllByRole('listitem')
    expect(items.map((li) => li.textContent)).toEqual([
      expect.stringContaining('Apps domain'),
      expect.stringContaining('Public address'),
      expect.stringContaining('Certificate for the apps domain'),
    ])
    expect(items[0].textContent).toContain('set the apps domain in Settings')
    expect(screen.getByRole('link', { name: 'Settings' }).getAttribute('href')).toBe('/admin/settings#settings-applications')
    expect(screen.getByRole('link', { name: 'Settings, TLS certificate' }).getAttribute('href')).toBe('/admin/settings#settings-tls-certificate')
    expect(screen.getAllByLabelText('to do')).toHaveLength(2)
    expect(screen.getAllByLabelText('done')).toHaveLength(1)
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
