import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import { Targets } from './admin/Targets'
import { Sessions } from './admin/Sessions'
import { Events } from './audit/Events'
import { MyAccess } from './user/MyAccess'
import { MySessions } from './user/MySessions'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-10-30 walkthrough: a dashboard number opened its page unfiltered, so
// "1 refused connection" showed every event. The pages read their filters
// from the address the tile links to, show them, and drop them on request.

function Where() {
  const loc = useLocation()
  return <p data-testid="where">{loc.pathname + loc.search}</p>
}

function at(path: string, element: React.ReactNode, route: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path={route} element={<>{element}<Where /></>} />
      </Routes>
    </MemoryRouter>,
  )
}

/** The query of the last call to an API path, as a URLSearchParams. */
function lastQuery(get: ReturnType<typeof vi.spyOn>, path: string): URLSearchParams {
  const calls = get.mock.calls.map((c: unknown[]) => String(c[0])).filter((u: string) => u.startsWith(path + '?') || u === path)
  const last = calls[calls.length - 1] ?? ''
  return new URLSearchParams(last.split('?')[1] ?? '')
}

describe('Audit events opened from a dashboard number', () => {
  it('asks for the counted events and shows the filters it was given', async () => {
    const get = vi.spyOn(api, 'get').mockImplementation(async (p: string) => {
      if (p.startsWith('/audit/events')) return { items: [] } as never
      if (p === '/audit/facets') return { actions: ['user.login'], object_types: [] } as never
      return {} as never
    })
    at('/admin/events?action=session.connect&outcome=failure&range=24h&routine=1', <Events />, '/admin/events')
    await waitFor(() => expect(lastQuery(get, '/audit/events').get('outcome')).toBe('failure'))
    const q = lastQuery(get, '/audit/events')
    expect(q.get('action')).toBe('session.connect')
    expect(q.has('exclude')).toBe(false) // routine=1: every event, as the count
    const from = Date.parse(q.get('from') ?? '')
    expect(Math.abs(Date.now() - 24 * 3600_000 - from)).toBeLessThan(60_000)
    // The form says what the list holds, an action the log has not yet
    // listed among its facets included.
    expect((screen.getByLabelText('Action') as HTMLSelectElement).value).toBe('session.connect')
    expect((screen.getByLabelText('Outcome') as HTMLSelectElement).value).toBe('failure')
    expect((screen.getByLabelText('Time') as HTMLSelectElement).value).toBe('24h')
    expect((screen.getByLabelText(/Show routine events/) as HTMLInputElement).checked).toBe(true)

    // Reset drops them all, from the list and the address.
    await userEvent.setup().click(screen.getByRole('button', { name: 'Reset' }))
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/admin/events'))
    await waitFor(() => expect(lastQuery(get, '/audit/events').has('outcome')).toBe(false))
    expect(lastQuery(get, '/audit/events').get('exclude')).toBe('audit.read,session.connect:success')
  })

  it('puts the filters a reviewer applies into the address', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => {
      if (p.startsWith('/audit/events')) return { items: [] } as never
      if (p === '/audit/facets') return { actions: ['user.login'], object_types: [] } as never
      return {} as never
    })
    at('/audit/events', <Events />, '/audit/events')
    const user = userEvent.setup()
    await user.selectOptions(await screen.findByLabelText('Outcome'), 'failure')
    await user.click(screen.getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/audit/events?outcome=failure'))
  })
})

describe('Sessions opened from a dashboard number', () => {
  it('asks for open sessions, or those started in the window', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    at('/admin/sessions?open=1&range=24h', <Sessions />, '/admin/sessions')
    await waitFor(() => expect(lastQuery(get, '/sessions').get('open')).toBe('true'))
    const from = Date.parse(lastQuery(get, '/sessions').get('from') ?? '')
    expect(Math.abs(Date.now() - 24 * 3600_000 - from)).toBeLessThan(60_000)
    expect((screen.getByLabelText('Live only') as HTMLInputElement).checked).toBe(true)
    expect((screen.getByLabelText('Started') as HTMLSelectElement).value).toBe('24h')

    await userEvent.setup().click(screen.getByLabelText('Live only'))
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/admin/sessions?range=24h'))
    await waitFor(() => expect(lastQuery(get, '/sessions').has('open')).toBe(false))
  })
})

describe('Hosts opened from a dashboard number', () => {
  it('lists the hosts needing attention, says so, and drops it on request', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    at('/admin/hosts?attention=1&status=active', <Targets />, '/admin/hosts')
    await waitFor(() => expect(lastQuery(get, '/targets').get('attention')).toBe('true'))
    expect(lastQuery(get, '/targets').get('status')).toBe('active')
    expect(lastQuery(get, '/targets').get('kind')).toBe('host')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Needing attention: remove filter' }))
    await waitFor(() => expect(lastQuery(get, '/targets').has('attention')).toBe(false))
    expect(screen.getByTestId('where').textContent).toBe('/admin/hosts?status=active')
    expect(screen.getByRole('button', { name: 'Active only: remove filter' })).toBeDefined()
  })
})

describe('The access portal strip', () => {
  it('opens the open sessions only', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
    at('/sessions?open=1', <MySessions />, '/sessions')
    await waitFor(() => expect(lastQuery(get, '/me/sessions').get('open')).toBe('true'))
    expect(await screen.findByText('No open sessions.')).toBeDefined()
  })

  it('opens the pending requests, or the grants about to end', async () => {
    const soon = new Date(Date.now() + 10 * 60_000).toISOString()
    const later = new Date(Date.now() + 5 * 3600_000).toISOString()
    const base = { protocol: 'ssh', reason: 'x', requested_minutes: 60, created_at: '2026-10-30T09:00:00Z' }
    vi.spyOn(api, 'get').mockResolvedValue({
      items: [
        { ...base, id: 'r1', status: 'pending', target_name: 'waiting-box' },
        { ...base, id: 'r2', status: 'approved', expires_at: soon, target_name: 'ending-box' },
        { ...base, id: 'r3', status: 'approved', expires_at: later, target_name: 'fine-box' },
      ],
    } as never)
    at('/access?show=pending', <MyAccess />, '/access')
    expect(await screen.findByText('waiting-box')).toBeDefined()
    expect(screen.queryByText('ending-box')).toBeNull()
    expect(screen.getByRole('button', { name: 'Pending: remove filter' })).toBeDefined()
    cleanup()
    at('/access?show=expiring', <MyAccess />, '/access')
    expect(await screen.findByText('ending-box')).toBeDefined()
    expect(screen.queryByText('fine-box')).toBeNull()
    expect(screen.queryByText('waiting-box')).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Expiring within the hour: remove filter' }))
    expect(await screen.findByText('fine-box')).toBeDefined()
  })
})
