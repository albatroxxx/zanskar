import { describe, expect, it } from 'vitest'
import { ApiError, errorMessage } from './client'

// M22: every error carries the request id, which finds the gateway's log
// lines. A server error is the one a user reports, so it shows the id.
describe('errorMessage', () => {
  it('adds the reference to a server error', () => {
    const err = new ApiError(500, { code: 'internal', message: 'internal error', request_id: '3f2a9c0b1d2e4f5a' }, 'failed')
    expect(errorMessage(err)).toBe('internal error (reference 3f2a9c0b1d2e4f5a)')
  })

  it('leaves a refusal as the gateway worded it', () => {
    const err = new ApiError(409, { code: 'conflict', message: 'a target with that name exists', request_id: '3f2a9c0b1d2e4f5a' }, 'failed')
    expect(errorMessage(err)).toBe('a target with that name exists')
  })

  it('has nothing to add without an id', () => {
    expect(errorMessage(new ApiError(502, null, 'Bad Gateway'))).toBe('Bad Gateway')
  })
})
