import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { ApiError } from '../api/client'
import { Confirm } from './ui'

afterEach(cleanup)

function failWith(err: unknown) {
  render(<Confirm title="Delete web-01?" body="It leaves every list." confirmLabel="Delete" onConfirm={() => Promise.reject(err)} onClose={() => {}} />)
  return userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }))
}

// B26: the dialog printed the error's bare message, so a server error lost
// the reference that finds its log lines, and an expired session got a
// second message under the session dialog that already says so.
describe('Confirm, when the action fails', () => {
  it('shows a server error with its reference', async () => {
    await failWith(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-7' }, '500'))
    expect((await screen.findByRole('alert')).textContent).toBe('database is locked (reference req-7)')
  })

  it('leaves an expired session to the session dialog', async () => {
    const err = new ApiError(401, { code: 'unauthenticated', message: 'sign in required' }, '401')
    err.sessionEnded = true
    await failWith(err)
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDefined()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
