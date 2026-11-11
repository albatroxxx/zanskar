import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { Applications } from './Applications'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const app = (id: string, name: string, endpoints: { name: string; url: string }[]) => ({
  id, name, address: '', os_family: 'other', ports: {}, capabilities: [], host_key_fingerprint: null, host_key_status: 'unknown',
  tls_fingerprint: null, winrm_tls_fingerprint: null, tags: {}, status: 'active', state: 'active', tls_status: 'none', winrm_tls_status: 'none',
  notes: '', credentials: {}, created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z', last_probed_at: null,
  app_upstream: `https://${name}.example`, app_endpoints: endpoints,
})

function mount() {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/applications/readiness') return { ready: true, checks: [] } as never
    if (path.startsWith('/targets')) {
      return { items: [app('a1', 'wiki', [{ name: 'api', url: 'https://api.example' }, { name: 'sso', url: 'https://sso.example' }]), app('a2', 'plain', [])] } as never
    }
    return { items: [] } as never
  })
  render(
    <MemoryRouter>
      <Applications />
    </MemoryRouter>,
  )
}

// The owner, 2026-11-11: "+1" after an upstream said there were more and
// showed them only in a tooltip. A toggle lists every other endpoint in the row.
describe('Applications, other endpoints', () => {
  it('lists every other endpoint behind a toggle in the row', async () => {
    mount()
    const row = (await screen.findByText('wiki')).closest('tr')!
    const toggle = within(row).getByRole('button', { name: 'Show 2 other endpoints' })
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    expect(within(row).queryByText('https://api.example')).toBeNull()

    await userEvent.setup().click(toggle)
    expect(toggle.getAttribute('aria-expanded')).toBe('true')
    expect(toggle.getAttribute('aria-label')).toBe('Hide 2 other endpoints')
    const items = within(row).getAllByRole('listitem').map((li) => li.textContent)
    expect(items).toEqual(['api https://api.example', 'sso https://sso.example'])

    // An application with no other endpoint has no toggle.
    const plain = screen.getByText('plain').closest('tr')!
    expect(within(plain).queryByRole('button', { name: /other endpoint/ })).toBeNull()
  })
})
