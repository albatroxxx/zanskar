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
  named: false, approvers: [], may_decide: true,
}
const named: AccessRequest = { ...unnamed, id: 'r2', username: 'carol', target_name: 'db-1', reason: 'migration', named: true, approvers: [{ kind: 'group', id: 'g1', name: 'ops' }, { kind: 'user', id: 'u9', name: 'ana' }], may_decide: false }
const activeNamed: AccessRequest = { ...named, id: 'r3', target_name: 'db-2', status: 'approved', state: 'approved', approved_minutes: 30, expires_at: '2026-11-16T12:00:00Z' }
// A grant naming the administrator themself (review R1): the gateway says
// they may decide, and the queue offers it.
const namesMe: AccessRequest = { ...named, id: 'r4', username: 'dan', target_name: 'db-3', reason: 'restore', approvers: [{ kind: 'user', id: 'u1', name: 'root' }], may_decide: true }
// An approver deleted since the grant named them (review R3): no name comes
// back; the id stands in rather than an empty cell.
const ghost: AccessRequest = { ...named, id: 'r5', username: 'eve', target_name: 'db-4', reason: 'audit', approvers: [{ kind: 'user', id: 'u-gone-1234' }] }

// ADR 0049: where a grant names approvers, they alone decide; the
// administrator sees the request with its approvers and keeps Revoke. The
// gateway's may_decide, not the console's reading of named, says which rows
// carry Approve and Deny (review R1), so an administrator a grant names
// decides from here.
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

  it('offers Approve and Deny on a named request the gateway says the administrator may decide', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.includes('status=pending') ? [named, namesMe] : [] }) as never)
    render(<MemoryRouter><Approvals /></MemoryRouter>)
    const dan = (await screen.findByText('db-3')).closest('tr') as HTMLElement
    expect(within(dan).getByText('root')).toBeDefined()
    expect(within(dan).getByRole('button', { name: 'Approve…' })).toBeDefined()
    expect(within(dan).getByRole('button', { name: 'Deny' })).toBeDefined()
    const carol = screen.getByText('db-1').closest('tr') as HTMLElement
    expect(within(carol).queryByRole('button')).toBeNull()
  })

  it('shows the id of an approver who no longer exists', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.includes('status=pending') ? [ghost] : [] }) as never)
    render(<MemoryRouter><Approvals /></MemoryRouter>)
    const eve = (await screen.findByText('db-4')).closest('tr') as HTMLElement
    expect(within(eve).getByText('u-gone-1234')).toBeDefined()
  })
})
