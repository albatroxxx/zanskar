import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { api } from './api/client'
import { AuthProvider } from './auth/AuthContext'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function signedIn(roles: string[], pendingForMe: unknown[] = []) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/auth/me') return { user: { id: 'u1', username: 'pat', display_name: 'Pat', status: 'active', roles }, csrf_token: 't', mfa_enrolled: true } as never
    if (path === '/access-requests?scope=mine&status=pending') return { items: pendingForMe } as never
    return { items: [] } as never
  })
}

// A request a grant names pat for, as the mail link would open it.
const namesPat = {
  id: 'r1', user_id: 'u2', username: 'bob', target_id: 't1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy',
  requested_minutes: 60, status: 'pending', state: 'pending', created_at: '2026-11-16T10:00:00Z', updated_at: '2026-11-16T10:00:00Z',
  named: true, approvers: [{ kind: 'user', id: 'u1', name: 'pat' }], may_decide: true,
}

function open(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ADR 0049: an approver decides from a portal of their own, reached from the
// access portal's nav; the role alone opens it, and nothing else does.
describe('the approver\'s portal', () => {
  it('shows an approver the Approvals item in the access portal, leading to their queue', async () => {
    signedIn(['user', 'approver'])
    open('/')
    const item = await screen.findByRole('link', { name: 'Approvals' })
    expect(item.getAttribute('href')).toBe('/approvals')
  })

  it('shows no Approvals item to a user without the role', async () => {
    signedIn(['user'])
    open('/')
    await screen.findByRole('heading', { name: 'Targets' })
    expect(screen.queryByRole('link', { name: 'Approvals' })).toBeNull()
  })

  it('opens the queue for an approver, with a way back to the access portal', async () => {
    signedIn(['user', 'approver'])
    open('/approvals')
    expect(await screen.findByRole('heading', { name: 'Approvals' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'Access portal' }).getAttribute('href')).toBe('/')
    expect(screen.getByText('approvals')).toBeDefined()
  })

  it('opens the queue for an account holding approver alone, with no access portal to go back to', async () => {
    signedIn(['approver'])
    open('/approvals')
    expect(await screen.findByRole('heading', { name: 'Approvals' })).toBeDefined()
    expect(screen.queryByRole('link', { name: 'Access portal' })).toBeNull()
  })

  it('keeps a user without the role out of it', async () => {
    signedIn(['user'])
    open('/approvals?request=r1')
    expect(await screen.findByRole('heading', { name: 'Targets' })).toBeDefined()
    expect(screen.queryByRole('heading', { name: 'Approvals' })).toBeNull()
  })

  // Review R1: an administrator is admitted wherever an approver is (ADR
  // 0049, 1); one a grant names follows the mail link here and the request
  // opens, rather than landing on the dashboard with nothing opened.
  it('admits an administrator a grant names, with the request the link carries', async () => {
    signedIn(['admin'], [namesPat])
    open('/approvals?request=r1')
    expect(await screen.findByRole('heading', { name: 'Approvals' })).toBeDefined()
    expect(await screen.findByRole('dialog', { name: 'Approve bob on web-1' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'Admin' }).getAttribute('href')).toBe('/admin')
  })

  it('shows an administrator no Approvals item in the access portal', async () => {
    signedIn(['admin'])
    open('/')
    await screen.findByRole('heading', { name: 'Targets' })
    expect(screen.queryByRole('link', { name: 'Approvals' })).toBeNull()
  })

  it('offers an auditor who approves a switch to their queue', async () => {
    signedIn(['auditor', 'approver'])
    open('/audit')
    expect(await screen.findByRole('link', { name: 'Events' })).toBeDefined()
    expect(screen.getByRole('link', { name: 'Approvals' }).getAttribute('href')).toBe('/approvals')
  })
})
