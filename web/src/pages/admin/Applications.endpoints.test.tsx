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
// showed them only in a tooltip; 1.19.2's "+1 ▾" pill opened them inside the
// cell and grew the row. 2026-11-12: Policies' disclosure after the address,
// opening a row of its own beneath the application's.
describe('Applications, other endpoints', () => {
  it('opens every other endpoint in a row beneath, by mouse or keyboard', async () => {
    mount()
    const user = userEvent.setup()
    const row = (await screen.findByText('wiki')).closest('tr')!
    const toggle = within(row).getByRole('button', { name: '2 other endpoints' })
    expect(toggle.textContent).toBe('+2')
    expect(toggle.className).toContain('expander')
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    const id = toggle.getAttribute('aria-controls')!
    expect(document.getElementById(id)).toBeNull()
    // The address is the cell's own text, outside the button, so it can be selected.
    expect(toggle.textContent).not.toContain('https://wiki.example')
    expect(row.textContent).toContain('https://wiki.example')

    await user.click(toggle)
    expect(toggle.getAttribute('aria-expanded')).toBe('true')
    expect(toggle.getAttribute('aria-label')).toBe('2 other endpoints')
    const detail = document.getElementById(id)!
    expect(detail.previousElementSibling).toBe(row)
    expect(within(detail).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['api https://api.example', 'sso https://sso.example'])
    expect(within(row).queryByRole('listitem')).toBeNull()

    await user.click(toggle)
    expect(document.getElementById(id)).toBeNull()
    toggle.focus()
    await user.keyboard('{Enter}')
    expect(toggle.getAttribute('aria-expanded')).toBe('true')

    // An application with no other endpoint has no disclosure.
    const plain = screen.getByText('plain').closest('tr')!
    expect(within(plain).queryByRole('button', { name: /other endpoint/ })).toBeNull()
  })
})
