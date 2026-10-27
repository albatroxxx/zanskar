import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AuditEvent } from '../../api/types'
import { Events } from './Events'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const event = (id: number): AuditEvent => ({
  id, ts: '2026-10-06T10:00:00Z', actor_user_id: 'u1', actor_username: 'root', actor_ip: '127.0.0.1', action: 'target.update',
  object_type: 'target', object_id: 't1', outcome: 'success', details: {}, prev_hash: '', hash: '',
})

function mount() {
  const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/audit/verify') return { intact: true, checked: 1, last_id: 1, last_hash: '' } as never
    if (path === '/audit/facets') return { actions: ['user.login', 'target.update'], object_types: ['target'] } as never
    return { items: [event(1)], next_cursor: '' } as never
  })
  render(
    <MemoryRouter>
      <Events />
    </MemoryRouter>,
  )
  return get
}

const listCalls = (get: { mock: { calls: unknown[][] } }) => get.mock.calls.map((c) => String(c[0])).filter((p) => p.startsWith('/audit/events'))
const param = (url: string, key: string) => new URLSearchParams(url.slice(url.indexOf('?') + 1)).get(key)

// Review finding F1: "Last hour" asking for the last minute passed both Events
// tests, which never submitted the form with a value. The range a reviewer
// picks must become the from the API is asked for.
describe('Events, the filter form', () => {
  it('asks for the last hour when "Last hour" is applied', async () => {
    const get = mount()
    await screen.findByText('root')
    const user = userEvent.setup()
    const before = Date.now()
    await user.selectOptions(screen.getByLabelText('Time'), 'Last hour')
    await user.click(screen.getByRole('button', { name: 'Apply filters' }))
    const last = listCalls(get).at(-1) ?? ''
    const from = new Date(param(last, 'from') ?? '').getTime()
    expect(Math.abs(from - (before - 3600_000))).toBeLessThan(5_000)
    expect(param(last, 'to')).toBeFalsy()
  })

  it('asks for the last 24 hours for that range, and for nothing when "Any time" is chosen', async () => {
    const get = mount()
    await screen.findByText('root')
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('Time'), 'Last 24 hours')
    await user.click(screen.getByRole('button', { name: 'Apply filters' }))
    let last = listCalls(get).at(-1) ?? ''
    const from = new Date(param(last, 'from') ?? '').getTime()
    expect(Math.abs(Date.now() - 24 * 3600_000 - from)).toBeLessThan(5_000)
    await user.selectOptions(screen.getByLabelText('Time'), 'Any time')
    await user.click(screen.getByRole('button', { name: 'Apply filters' }))
    last = listCalls(get).at(-1) ?? ''
    expect(param(last, 'from')).toBeFalsy()
  })

  it('sends the actor, action and object type exactly as chosen', async () => {
    const get = mount()
    await screen.findByText('root')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('User'), 'alice')
    await user.selectOptions(screen.getByLabelText('Action'), 'user.login')
    await user.selectOptions(screen.getByLabelText('Object type'), 'target')
    await user.click(screen.getByRole('button', { name: 'Apply filters' }))
    const last = listCalls(get).at(-1) ?? ''
    expect(param(last, 'actor')).toBe('alice')
    expect(param(last, 'action')).toBe('user.login')
    expect(param(last, 'object_type')).toBe('target')
  })
})
