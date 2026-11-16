import { cleanup, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AccessRequest } from '../../api/types'
import { Approvals } from './Approvals'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const unnamed: AccessRequest = {
  id: 'r1', user_id: 'u1', username: 'bob', target_id: 't1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy',
  requested_minutes: 60, status: 'pending', state: 'pending', created_at: '2026-11-16T10:00:00Z', updated_at: '2026-11-16T10:00:00Z',
  named: false, approvers: [],
}
const named: AccessRequest = { ...unnamed, id: 'r2', username: 'carol', target_name: 'db-1', reason: 'migration', named: true, approvers: [{ kind: 'group', id: 'g1', name: 'ops' }, { kind: 'user', id: 'u9', name: 'ana' }] }
const activeNamed: AccessRequest = { ...named, id: 'r3', target_name: 'db-2', status: 'approved', state: 'approved', approved_minutes: 30, expires_at: '2026-11-16T12:00:00Z' }

// ADR 0049: where a grant names approvers, they alone decide; the
// administrator sees the request with its approvers and keeps Revoke.
describe('the admin queue with named approvers', () => {
  it('names the approvers, offers no decision on their requests, and keeps Revoke', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.includes('status=pending') ? [unnamed, named] : [activeNamed] }) as never)
    render(<MemoryRouter><Approvals /></MemoryRouter>)

    expect(await screen.findByRole('columnheader', { name: 'Approvers' })).toBeDefined()
    const bob = (await screen.findByText('web-1')).closest('tr') as HTMLElement
    const carol = screen.getByText('db-1').closest('tr') as HTMLElement
    expect(within(bob).getByText('—')).toBeDefined()
    expect(within(bob).getByRole('button', { name: 'Approve…' })).toBeDefined()
    expect(within(bob).getByRole('button', { name: 'Deny' })).toBeDefined()
    expect(within(carol).getByText('ops, ana')).toBeDefined()
    expect(within(carol).queryByRole('button')).toBeNull()
    expect(within(carol).queryByText('yours')).toBeNull()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeDefined()
  })
})
