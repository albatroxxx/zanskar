import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { PolicyReview } from './PolicyReview'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 4 (ADR 0040): an access review lists who a policy covers
// and when each last used it; the administrator keeps or removes each.

const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString()
const view = (over: Record<string, unknown> = {}) => ({
  policy: { id: 'p1', name: 'host-access', description: '', enabled: true, subjects: [], grants: [], created_at: '', updated_at: '' },
  subjects: [
    { kind: 'group', id: 'g1', name: 'ops', people: [{ user_id: 'u1', username: 'ann', last_used_at: daysAgo(3) }], last_used_at: daysAgo(3) },
    { kind: 'user', id: 'u2', name: 'ben', people: [{ user_id: 'u2', username: 'ben' }] },
    { kind: 'user', id: 'u3', name: 'cid', people: [{ user_id: 'u3', username: 'cid', last_used_at: daysAgo(200) }], last_used_at: daysAgo(200) },
  ],
  due: true,
  ...over,
})

function mount() {
  render(
    <MemoryRouter initialEntries={['/admin/policies/p1/review']}>
      <Routes>
        <Route path="/admin/policies/:id/review" element={<PolicyReview />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('Access review', () => {
  it('shows each subject, its people and their last use, flagging the unused', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(view() as never)
    mount()
    expect(await screen.findByRole('heading', { name: 'Review host-access' })).toBeDefined()
    expect(screen.getByText('Never reviewed.')).toBeDefined()
    expect(screen.getByText('review due')).toBeDefined()
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows[0].textContent).toContain('ann')
    expect(within(rows[1]).getByText('never used')).toBeDefined()
    expect(within(rows[2]).getByText('unused 90+ days')).toBeDefined()
  })

  it('removes what is marked, with the note, and says what it did', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(view() as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue(view({ subjects: [view().subjects[0]], due: false, reviewer_name: 'root', policy: { ...view().policy, reviewed_at: daysAgo(0) } }) as never)
    mount()
    const user = userEvent.setup()
    await user.click(await screen.findByLabelText('Remove ben'))
    await user.click(screen.getByLabelText('Remove cid'))
    await user.type(screen.getByPlaceholderText(/What this review found/), 'left the team')
    await user.click(screen.getByRole('button', { name: 'Remove 2 and complete review' }))
    expect(post).toHaveBeenCalledWith('/access-policies/p1/review', { remove: [{ kind: 'user', id: 'u2' }, { kind: 'user', id: 'u3' }], note: 'left the team' })
    expect(await screen.findByText('Review complete: 2 removed, 1 kept.')).toBeDefined()
    expect(screen.getByText(/Last reviewed .* by root/)).toBeDefined()
  })

  it('keeps everyone when nothing is marked', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(view() as never)
    const post = vi.spyOn(api, 'post').mockResolvedValue(view({ due: false }) as never)
    mount()
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Keep everyone and complete review' }))
    expect(post).toHaveBeenCalledWith('/access-policies/p1/review', { remove: [], note: '' })
  })
})
