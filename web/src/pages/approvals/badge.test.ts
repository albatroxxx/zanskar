import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { pendingForMe } from './badge'

afterEach(() => vi.restoreAllMocks())

// The approver's badge counts the requests in their scope that wait (ADR 0049).
describe('pendingForMe', () => {
  it('counts the pending requests in the caller\'s scope', async () => {
    const cached = vi.spyOn(api, 'cached').mockResolvedValue({ items: [{ id: 'a' }, { id: 'b' }] } as never)
    expect(await pendingForMe()).toBe(2)
    expect(cached).toHaveBeenCalledWith('/access-requests?scope=mine&status=pending', 30_000)
  })
})
