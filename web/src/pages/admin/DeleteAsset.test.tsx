import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { DeleteAsset } from './DeleteAsset'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// ADR 0036, amended 2026-10-30: deleting a target took every policy edited
// first. It now says what goes with it, and asks for the name.
describe('DeleteAsset', () => {
  it('says what the delete takes with it, and deletes once the name is typed', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({
      policies: [
        { policy_id: 'p1', name: 'prod-ssh', grants_removed: 0, no_grants_left: false },
        { policy_id: 'p2', name: 'jit-db', grants_removed: 1, no_grants_left: true },
      ],
      live_sessions: 1,
      open_requests: 2,
    } as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue(undefined as never)
    const onDeleted = vi.fn()
    render(<DeleteAsset name="web-01" path="/targets/t1" onClose={() => {}} onDeleted={onDeleted} />)
    const user = userEvent.setup()
    expect(await screen.findByText('Removes it from 2 policies: prod-ssh, jit-db')).toBeDefined()
    expect(screen.getByText('1 grant is left naming nothing and removed')).toBeDefined()
    expect(screen.getByText('jit-db is left with no grant and grants nobody')).toBeDefined()
    expect(screen.getByText('Ends 1 live session')).toBeDefined()
    expect(screen.getByText('Closes 2 open access requests')).toBeDefined()
    const button = screen.getByRole('button', { name: 'Delete' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    await user.type(screen.getByLabelText('Type web-01 to confirm'), 'web-0')
    expect(button.disabled).toBe(true)
    await user.type(screen.getByLabelText('Type web-01 to confirm'), '1')
    await user.click(button)
    expect(del).toHaveBeenCalledWith('/targets/t1')
    expect(onDeleted).toHaveBeenCalled()
  })

  it('says when nothing else names it', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ policies: [], live_sessions: 0, open_requests: 0 } as never)
    render(<DeleteAsset name="fleet" path="/autoscaling-groups/a1" onClose={() => {}} onDeleted={() => {}} />)
    expect(await screen.findByText('No policy, session or request names it.')).toBeDefined()
  })
})
