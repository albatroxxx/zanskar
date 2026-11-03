import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { AccessRequest } from '../../api/types'
import { onBadgeCount } from '../../components/badges'
import { Approvals } from './Approvals'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 3: a notification links to the request, never to a token
// that approves it (ADR 0039). The link opens the request; approving asks
// for a recent authenticator code when the gateway says so.

const pending: AccessRequest = {
  id: 'r1', user_id: 'u1', username: 'bob', target_id: 't1', target_name: 'web-1', protocol: 'ssh', reason: 'deploy',
  requested_minutes: 60, status: 'pending', created_at: '2026-11-03T10:00:00Z', updated_at: '2026-11-03T10:00:00Z',
}
const other: AccessRequest = { ...pending, id: 'r3', username: 'dan', target_name: 'db-1' }
const decided: AccessRequest = {
  ...pending, id: 'r9', status: 'approved', approver_username: 'root', decided_at: '2026-11-03T10:05:00Z', approved_minutes: 60,
}

const stepUp = () => new ApiError(403, { code: 'step_up_required', message: 'prove your authenticator first' }, '403')
const wrongCode = () => new ApiError(401, { code: 'invalid_code', message: 'invalid code' }, '401')

function open(at: string, post: (path: string, body?: unknown) => Promise<unknown> = async () => ({})) {
  const get = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path.includes('status=pending')) return { items: [pending, other] } as never
    if (path.includes('status=approved')) return { items: [] } as never
    if (path === '/access-requests/r9') return decided as never
    throw new ApiError(404, { code: 'not_found', message: 'not found' }, '404')
  })
  const p = vi.spyOn(api, 'post').mockImplementation(post as never)
  render(<MemoryRouter initialEntries={[at]}><Approvals /></MemoryRouter>)
  return { get, post: p }
}

describe('a link to one request', () => {
  it('opens the approve dialog for a waiting request and marks its row', async () => {
    open('/admin/approvals?request=r1')
    expect(await screen.findByRole('dialog', { name: 'Approve bob on web-1' })).toBeDefined()
    const rows = screen.getAllByRole('row').filter((r) => r.getAttribute('aria-current') === 'true')
    expect(rows).toHaveLength(1)
    expect(rows[0].textContent).toContain('bob')
  })

  it('opens it once: closed, it stays closed', async () => {
    open('/admin/approvals?request=r1')
    await screen.findByRole('dialog')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.setup().click(screen.getAllByRole('button', { name: 'Deny' })[1])
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('says what became of a request decided meanwhile', async () => {
    open('/admin/approvals?request=r9')
    expect(await screen.findByText(/bob's request for web-1 was already approved by root/)).toBeDefined()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('says a request it cannot find was not found', async () => {
    open('/admin/approvals?request=nope')
    expect(await screen.findByText('The request in the link was not found.')).toBeDefined()
  })

  // 2026-11-03 live audit, Q12: the page hands the pending count to the
  // sidebar's badge rather than the badge reading it a third time.
  it('hands the pending count to the sidebar badge', async () => {
    const counts: number[] = []
    const off = onBadgeCount('/admin/approvals', (n) => counts.push(n))
    open('/admin/approvals')
    await screen.findByText('bob')
    off()
    expect(counts).toEqual([2])
  })

  it('reads no single request without a link', async () => {
    const { get } = open('/admin/approvals')
    await screen.findByText('bob')
    expect(get.mock.calls.map(([p]) => p).filter((p) => !p.includes('status='))).toEqual([])
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('approving with a recent code', () => {
  it('asks for the code when the gateway does, proves it, then approves', async () => {
    let proved = false
    const { post } = open('/admin/approvals?request=r1', async (path, body) => {
      if (path === '/auth/mfa/step-up') {
        expect(body).toEqual({ code: '123456' })
        proved = true
        return {}
      }
      if (path === '/access-requests/r1/approve') {
        if (!proved) throw stepUp()
        return { ...pending, status: 'approved' }
      }
      throw new Error('unexpected ' + path)
    })
    const user = userEvent.setup()
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('button', { name: /Approve for 60 min/ }))
    const field = await screen.findByLabelText('Authenticator code')
    expect(screen.queryByRole('alert')).toBeNull()
    expect((screen.getByRole('button', { name: /Approve for 60 min/ }) as HTMLButtonElement).disabled).toBe(true)
    await user.type(field, '123456')
    await user.click(screen.getByRole('button', { name: /Approve for 60 min/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(post.mock.calls.map(([p]) => p)).toEqual(['/access-requests/r1/approve', '/auth/mfa/step-up', '/access-requests/r1/approve'])
  })

  it('keeps the dialog and says so when the code is wrong', async () => {
    const { post } = open('/admin/approvals?request=r1', async (path) => {
      if (path === '/auth/mfa/step-up') throw wrongCode()
      throw stepUp()
    })
    const user = userEvent.setup()
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('button', { name: /Approve for 60 min/ }))
    await user.type(await screen.findByLabelText('Authenticator code'), '000000')
    await user.click(screen.getByRole('button', { name: /Approve for 60 min/ }))
    expect(await screen.findByText(/invalid code/)).toBeDefined()
    expect(screen.getByRole('dialog')).toBeDefined()
    expect(post.mock.calls.filter(([p]) => p === '/access-requests/r1/approve')).toHaveLength(1)
  })

  it('a fresh dialog starts without the code field', async () => {
    open('/admin/approvals?request=r1', async () => {
      throw stepUp()
    })
    const user = userEvent.setup()
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('button', { name: /Approve for 60 min/ }))
    await screen.findByLabelText('Authenticator code')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await user.click(screen.getAllByRole('button', { name: 'Approve…' })[1])
    expect(await screen.findByRole('dialog', { name: 'Approve dan on db-1' })).toBeDefined()
    expect(screen.queryByLabelText('Authenticator code')).toBeNull()
  })
})
